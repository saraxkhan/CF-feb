import os
import uuid
import zipfile
import json
import time
import base64
import threading
from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context
from utils.data_loader import load_data
from utils.placeholder_extractor import extract_placeholders
from utils.certificate_generator import generate_certificate
from utils.database import init_db, store_certificate, get_certificate
from utils.crypto_utils import generate_certificate_id, sign_certificate, compute_certificate_hash, verify_signature

app = Flask(__name__)

SECRET_KEY = os.environ.get('CERT_SECRET_KEY', 'udemy-123')
BASE_URL    = os.environ.get('BASE_URL', 'https://certifyfast.onrender.com')

BASE_DIR   = "/tmp/certifyfast"
UPLOADS    = os.path.join(BASE_DIR, "uploads")
OUTPUT     = os.path.join(BASE_DIR, "output")
SIGNATURES = os.path.join(BASE_DIR, "signatures")
ZIPS       = os.path.join(BASE_DIR, "zips")
os.makedirs(UPLOADS,    exist_ok=True)
os.makedirs(OUTPUT,     exist_ok=True)
os.makedirs(SIGNATURES, exist_ok=True)
os.makedirs(ZIPS,       exist_ok=True)

init_db()

# In-memory job store  { job_id: { status, progress, total, success, errors, zip_path, error_msg } }
_jobs = {}
_jobs_lock = threading.Lock()


def _compute_mapping(df_columns, placeholder_keys):
    col_map = {col.strip().lower(): col for col in df_columns}
    matched, matched_keys = [], set()
    for key in placeholder_keys:
        if key in col_map:
            matched.append({"placeholder": key, "column": col_map[key]})
            matched_keys.add(key)
    unmatched = [k for k in placeholder_keys if k not in matched_keys]
    return matched, unmatched


# ─────────────────────────────────────────────────────────────
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
        template_file  = request.files.get("template")
        data_file      = request.files.get("data")
        signature_file = request.files.get("signature")

        if not template_file or not data_file:
            return jsonify({"error": "Both a PDF template and a data file are required."}), 400

        sid       = uuid.uuid4().hex[:10]
        tmpl_ext  = os.path.splitext(template_file.filename)[1] or ".pdf"
        data_ext  = os.path.splitext(data_file.filename)[1]     or ".xlsx"
        tmpl_path = os.path.join(UPLOADS, f"{sid}_template{tmpl_ext}")
        data_path = os.path.join(UPLOADS, f"{sid}_data{data_ext}")

        template_file.save(tmpl_path)
        data_file.save(data_path)

        sig_path = None
        if signature_file and signature_file.filename:
            sig_ext  = os.path.splitext(signature_file.filename)[1] or ".png"
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
            "session_id":    sid,
            "placeholders":  list(placeholders.keys()),
            "columns":       df.columns.tolist(),
            "matched":       matched,
            "unmatched":     unmatched,
            "total":         len(df),
            "preview":       preview,
            "has_signature": sig_path is not None,
        })

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# Background worker
# ─────────────────────────────────────────────────────────────
def _run_generation(job_id, tmpl_path, data_path, sig_path,
                    qr_position, sig_position):
    import pandas as pd

    def update(status, **kw):
        with _jobs_lock:
            _jobs[job_id].update({"status": status, **kw})

    def safe_str(val):
        if isinstance(val, pd.Timestamp):
            return val.strftime('%Y-%m-%d')
        return str(val).strip()

    try:
        placeholders = extract_placeholders(tmpl_path)
        df           = load_data(data_path)
    except Exception as e:
        update("error", error_msg=f"Failed to read files: {e}")
        return

    if not placeholders:
        update("error", error_msg="No placeholders found in template.")
        return

    total = len(df)
    update("running", total=total, done=0, success=0, errors=[])

    zip_path = os.path.join(ZIPS, f"{job_id}.zip")
    errors, success_count = [], 0

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for idx, (_, row) in enumerate(df.iterrows()):
                out_pdf = None
                try:
                    raw_data  = {col: safe_str(row[col]) for col in df.columns}
                    fname_val = safe_str(row[df.columns[0]])
                    if not fname_val or fname_val.lower() == "nan":
                        fname_val = f"certificate_{idx+1}"
                    safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in fname_val).strip() or f"certificate_{idx+1}"
                    out_pdf   = os.path.join(OUTPUT, f"{job_id}_{idx}.pdf")

                    cert_id  = generate_certificate_id()
                    cert_data = {'cert_id': cert_id}
                    for col in df.columns:
                        cl = col.lower().strip()
                        if cl in ['name', 'student', 'recipient', 'full_name']:
                            cert_data['name']   = safe_str(row[col])
                        elif cl in ['course', 'subject', 'program', 'course_name']:
                            cert_data['course'] = safe_str(row[col])
                        elif cl in ['date', 'issue_date', 'completion_date', 'cert_date']:
                            cert_data['date']   = safe_str(row[col])

                    if 'name'   not in cert_data: cert_data['name']   = safe_str(row[df.columns[0]]) if len(df.columns) > 0 else 'Unknown'
                    if 'course' not in cert_data: cert_data['course'] = safe_str(row[df.columns[1]]) if len(df.columns) > 1 else 'Unknown'
                    if 'date'   not in cert_data:
                        from datetime import datetime
                        cert_data['date'] = safe_str(row[df.columns[2]]) if len(df.columns) > 2 else datetime.now().strftime('%Y-%m-%d')

                    signature  = sign_certificate(cert_data, SECRET_KEY)
                    data_hash  = compute_certificate_hash(cert_data)
                    verification_url = f"{BASE_URL}/verify/{cert_id}"

                    generate_certificate(
                        tmpl_path, out_pdf, raw_data, placeholders,
                        cert_id=cert_id, verification_url=verification_url,
                        qr_position=qr_position,
                        signature_path=sig_path, sig_position=sig_position,
                    )
                    store_certificate(cert_id, cert_data['name'], cert_data['course'],
                                      cert_data['date'], signature, data_hash, additional_data=raw_data)

                    if os.path.exists(out_pdf) and os.path.getsize(out_pdf) > 0:
                        zf.write(out_pdf, arcname=f"{safe_name}.pdf")
                        success_count += 1
                    else:
                        errors.append(f"Row {idx+1}: PDF not created")

                except Exception as e:
                    errors.append(f"Row {idx+1}: {str(e)[:150]}")
                finally:
                    if out_pdf and os.path.exists(out_pdf):
                        try: os.remove(out_pdf)
                        except: pass

                # Update progress after each cert
                with _jobs_lock:
                    _jobs[job_id].update(done=idx+1, success=success_count, errors=errors)

    except Exception as e:
        update("error", error_msg=f"Fatal ZIP error: {e}")
        return
    finally:
        for p in [tmpl_path, data_path]:
            if p and os.path.exists(p):
                try: os.remove(p)
                except: pass
        if sig_path and os.path.exists(sig_path):
            try: os.remove(sig_path)
            except: pass

    if success_count == 0:
        msg = "Failed to generate any certificates."
        if errors: msg += " First error: " + errors[0]
        update("error", error_msg=msg)
        if os.path.exists(zip_path):
            try: os.remove(zip_path)
            except: pass
        return

    update("done", zip_path=zip_path, success=success_count, errors=errors)


# ─────────────────────────────────────────────────────────────
# POST /api/generate  →  start job, return job_id immediately
# ─────────────────────────────────────────────────────────────
@app.route("/api/generate", methods=["POST"])
def generate():
    sid          = request.form.get("session_id", "")
    qr_position  = request.form.get("qr_position",  "bottom-right")
    sig_position = request.form.get("sig_position", "bottom-center")

    if not sid:
        return jsonify({"error": "Session expired. Please re-upload your files."}), 400

    # Find files
    tmpl_path = data_path = sig_path = None
    try:
        for f in os.listdir(UPLOADS):
            if f.startswith(f"{sid}_template"):   tmpl_path = os.path.join(UPLOADS, f)
            elif f.startswith(f"{sid}_data"):     data_path = os.path.join(UPLOADS, f)
        for f in os.listdir(SIGNATURES):
            if f.startswith(f"{sid}_signature"):  sig_path = os.path.join(SIGNATURES, f); break
    except Exception as e:
        return jsonify({"error": f"Could not find session files: {e}"}), 500

    if not tmpl_path or not data_path:
        return jsonify({"error": "Session expired. Please re-upload your files."}), 400

    job_id = uuid.uuid4().hex[:12]
    with _jobs_lock:
        _jobs[job_id] = {"status": "queued", "done": 0, "total": 0,
                         "success": 0, "errors": [], "zip_path": None, "error_msg": None}

    t = threading.Thread(target=_run_generation,
                         args=(job_id, tmpl_path, data_path, sig_path, qr_position, sig_position),
                         daemon=True)
    t.start()

    return jsonify({"job_id": job_id})


# ─────────────────────────────────────────────────────────────
# GET /api/job/<job_id>  →  SSE progress stream
# ─────────────────────────────────────────────────────────────
@app.route("/api/job/<job_id>")
def job_status(job_id):
    def stream():
        while True:
            with _jobs_lock:
                job = _jobs.get(job_id)

            if job is None:
                data = json.dumps({"type": "error", "message": "Job not found."})
                yield f"data: {data}\n\n"
                return

            status = job["status"]

            if status == "error":
                data = json.dumps({"type": "error", "message": job.get("error_msg", "Unknown error")})
                yield f"data: {data}\n\n"
                with _jobs_lock:
                    _jobs.pop(job_id, None)
                return

            elif status == "done":
                zip_path = job.get("zip_path")
                try:
                    with open(zip_path, "rb") as f:
                        zip_b64 = base64.b64encode(f.read()).decode("utf-8")
                    os.remove(zip_path)
                except Exception as e:
                    data = json.dumps({"type": "error", "message": f"Could not read ZIP: {e}"})
                    yield f"data: {data}\n\n"
                    return
                data = json.dumps({
                    "type":    "done",
                    "success": job["success"],
                    "total":   job["total"],
                    "errors":  job["errors"][:5],
                    "zip_b64": zip_b64,
                })
                yield f"data: {data}\n\n"
                with _jobs_lock:
                    _jobs.pop(job_id, None)
                return

            else:
                # queued or running — send progress ping
                data = json.dumps({
                    "type":    "progress",
                    "status":  status,
                    "done":    job["done"],
                    "total":   job["total"],
                    "success": job["success"],
                    "errors":  len(job["errors"]),
                })
                yield f"data: {data}\n\n"
                time.sleep(0.8)

    return Response(
        stream_with_context(stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True, threaded=True)
