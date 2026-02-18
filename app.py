import os
import uuid
import zipfile
import json
import time
import base64
import tempfile
from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context
from utils.data_loader import load_data
from utils.placeholder_extractor import extract_placeholders
from utils.certificate_generator import generate_certificate
from utils.database import init_db, store_certificate, get_certificate
from utils.crypto_utils import generate_certificate_id, sign_certificate, compute_certificate_hash, verify_signature

app = Flask(__name__)

SECRET_KEY = os.environ.get('CERT_SECRET_KEY', 'udemy-123')
BASE_URL = os.environ.get('BASE_URL', 'https://certifyfast.onrender.com')

BASE_DIR   = "/tmp/certifyfast"
UPLOADS    = os.path.join(BASE_DIR, "uploads")
OUTPUT     = os.path.join(BASE_DIR, "output")
SIGNATURES = os.path.join(BASE_DIR, "signatures")
os.makedirs(UPLOADS,    exist_ok=True)
os.makedirs(OUTPUT,     exist_ok=True)
os.makedirs(SIGNATURES, exist_ok=True)

init_db()


def _compute_mapping(df_columns, placeholder_keys):
    col_map = { col.strip().lower(): col for col in df_columns }
    matched, matched_keys = [], set()
    for key in placeholder_keys:
        if key in col_map:
            matched.append({ "placeholder": key, "column": col_map[key] })
            matched_keys.add(key)
    unmatched = [ k for k in placeholder_keys if k not in matched_keys ]
    return matched, unmatched


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/verify/<cert_id>")
def verify_page(cert_id):
    cert = get_certificate(cert_id)
    if not cert:
        return render_template("verify.html", found=False, cert_id=cert_id)
    cert_data = {'cert_id': cert['cert_id'], 'name': cert['name'],
                 'course': cert['course'], 'date': cert['date']}
    is_valid = verify_signature(cert_data, cert['signature'], SECRET_KEY)
    return render_template("verify.html", found=True, valid=is_valid, cert=cert)


@app.route("/api/verify/<cert_id>")
def verify_api(cert_id):
    cert = get_certificate(cert_id)
    if not cert:
        return jsonify({"found": False, "cert_id": cert_id, "message": "Certificate not found"}), 404
    cert_data = {'cert_id': cert['cert_id'], 'name': cert['name'],
                 'course': cert['course'], 'date': cert['date']}
    is_valid = verify_signature(cert_data, cert['signature'], SECRET_KEY)
    return jsonify({"found": True, "valid": is_valid, "certificate": {
        "id": cert['cert_id'], "recipient": cert['name'],
        "course": cert['course'], "issue_date": cert['date'], "issued_at": cert['created_at']
    }})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        template_file = request.files.get("template")
        data_file     = request.files.get("data")
        signature_file = request.files.get("signature")

        if not template_file or not data_file:
            return jsonify({"error": "Both a PDF template and a data file are required."}), 400

        sid = uuid.uuid4().hex[:10]
        tmpl_ext  = os.path.splitext(template_file.filename)[1] or ".pdf"
        data_ext  = os.path.splitext(data_file.filename)[1]     or ".xlsx"
        tmpl_path = os.path.join(UPLOADS, f"{sid}_template{tmpl_ext}")
        data_path = os.path.join(UPLOADS, f"{sid}_data{data_ext}")

        template_file.save(tmpl_path)
        data_file.save(data_path)

        sig_path = None
        if signature_file and signature_file.filename:
            sig_ext = os.path.splitext(signature_file.filename)[1] or ".png"
            sig_path = os.path.join(SIGNATURES, f"{sid}_signature{sig_ext}")
            signature_file.save(sig_path)

        placeholders = extract_placeholders(tmpl_path)
        df           = load_data(data_path)

        if not placeholders:
            return jsonify({"error": "No {{placeholders}} found in the PDF template."}), 400

        matched, unmatched = _compute_mapping(df.columns.tolist(), list(placeholders.keys()))

        preview = []
        for _, row in df.head(5).iterrows():
            preview.append({col: str(row[col]) for col in df.columns})

        return jsonify({
            "session_id":   sid,
            "placeholders": list(placeholders.keys()),
            "columns":      df.columns.tolist(),
            "matched":      matched,
            "unmatched":    unmatched,
            "total":        len(df),
            "preview":      preview,
            "has_signature": sig_path is not None
        })

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/generate", methods=["POST"])
def generate():
    """
    Streaming SSE endpoint. Sends progress events while generating,
    then sends the final ZIP as a base64 data event.
    """
    sid         = request.form.get("session_id", "")
    qr_position = request.form.get("qr_position", "bottom-right")
    sig_position= request.form.get("sig_position", "bottom-center")

    def event_stream():
        def send(event_type, **kwargs):
            data = json.dumps({"type": event_type, **kwargs})
            return f"data: {data}\n\n"

        if not sid:
            yield send("error", message="Session expired. Please re-upload your files.")
            return

        # Find saved files
        tmpl_path = data_path = sig_path = None
        try:
            for f in os.listdir(UPLOADS):
                if f.startswith(f"{sid}_template"):
                    tmpl_path = os.path.join(UPLOADS, f)
                elif f.startswith(f"{sid}_data"):
                    data_path = os.path.join(UPLOADS, f)
            for f in os.listdir(SIGNATURES):
                if f.startswith(f"{sid}_signature"):
                    sig_path = os.path.join(SIGNATURES, f)
                    break
        except Exception as e:
            yield send("error", message=f"Could not find session files: {str(e)}")
            return

        if not tmpl_path or not data_path:
            yield send("error", message="Session expired. Please re-upload your files.")
            return

        try:
            placeholders = extract_placeholders(tmpl_path)
            df = load_data(data_path)
        except Exception as e:
            yield send("error", message=f"Failed to read files: {str(e)}")
            return

        if not placeholders:
            yield send("error", message="No placeholders found in template.")
            return

        total = len(df)
        yield send("start", total=total)

        zip_path = os.path.join(OUTPUT, f"certificates_{sid}.zip")
        errors = []
        success_count = 0

        import pandas as pd

        def safe_str(val):
            if isinstance(val, pd.Timestamp):
                return val.strftime('%Y-%m-%d')
            return str(val).strip()

        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for idx, (_, row) in enumerate(df.iterrows()):
                    out_pdf = None
                    try:
                        raw_data = {col: safe_str(row[col]) for col in df.columns}

                        fname_val = safe_str(row[df.columns[0]])
                        if not fname_val or fname_val.lower() == "nan":
                            fname_val = f"certificate_{idx + 1}"

                        safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in fname_val).strip()
                        if not safe_name:
                            safe_name = f"certificate_{idx + 1}"

                        out_pdf = os.path.join(OUTPUT, f"{safe_name}_{idx}.pdf")

                        cert_id = generate_certificate_id()
                        cert_data = {'cert_id': cert_id}
                        for col in df.columns:
                            cl = col.lower().strip()
                            if cl in ['name', 'student', 'recipient', 'full_name']:
                                cert_data['name'] = safe_str(row[col])
                            elif cl in ['course', 'subject', 'program', 'course_name']:
                                cert_data['course'] = safe_str(row[col])
                            elif cl in ['date', 'issue_date', 'completion_date', 'cert_date']:
                                cert_data['date'] = safe_str(row[col])

                        if 'name' not in cert_data:
                            cert_data['name'] = safe_str(row[df.columns[0]]) if len(df.columns) > 0 else 'Unknown'
                        if 'course' not in cert_data:
                            cert_data['course'] = safe_str(row[df.columns[1]]) if len(df.columns) > 1 else 'Unknown'
                        if 'date' not in cert_data:
                            cert_data['date'] = safe_str(row[df.columns[2]]) if len(df.columns) > 2 else ''
                        if not cert_data.get('date'):
                            from datetime import datetime
                            cert_data['date'] = datetime.now().strftime('%Y-%m-%d')

                        signature  = sign_certificate(cert_data, SECRET_KEY)
                        data_hash  = compute_certificate_hash(cert_data)
                        verification_url = f"{BASE_URL}/verify/{cert_id}"

                        generate_certificate(
                            tmpl_path, out_pdf, raw_data, placeholders,
                            cert_id=cert_id, verification_url=verification_url,
                            qr_position=qr_position,
                            signature_path=sig_path, sig_position=sig_position
                        )

                        store_certificate(
                            cert_id, cert_data['name'], cert_data['course'],
                            cert_data['date'], signature, data_hash, additional_data=raw_data
                        )

                        if os.path.exists(out_pdf) and os.path.getsize(out_pdf) > 0:
                            zf.write(out_pdf, arcname=f"{safe_name}.pdf")
                            success_count += 1
                            try:
                                os.remove(out_pdf)
                            except:
                                pass
                        else:
                            errors.append(f"Row {idx+1}: PDF not created")

                    except Exception as e:
                        errors.append(f"Row {idx+1}: {str(e)[:150]}")
                        if out_pdf and os.path.exists(out_pdf):
                            try:
                                os.remove(out_pdf)
                            except:
                                pass

                    # Send progress update
                    yield send("progress", done=idx + 1, total=total,
                               success=success_count, errors=len(errors))

        except Exception as e:
            yield send("error", message=f"Fatal error during generation: {str(e)[:300]}")
            return
        finally:
            # Clean up session files
            for p in [tmpl_path, data_path]:
                if p and os.path.exists(p):
                    try:
                        os.remove(p)
                    except:
                        pass
            if sig_path and os.path.exists(sig_path):
                try:
                    os.remove(sig_path)
                except:
                    pass

        if success_count == 0:
            msg = "Failed to generate any certificates."
            if errors:
                msg += " First error: " + errors[0]
            yield send("error", message=msg)
            if os.path.exists(zip_path):
                os.remove(zip_path)
            return

        # Send ZIP as base64
        try:
            with open(zip_path, "rb") as f:
                zip_b64 = base64.b64encode(f.read()).decode("utf-8")
            os.remove(zip_path)
            yield send("done", success=success_count, total=total,
                       errors=errors[:5], zip_b64=zip_b64)
        except Exception as e:
            yield send("error", message=f"Failed to send ZIP: {str(e)}")

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering on Render
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True, threaded=True)

