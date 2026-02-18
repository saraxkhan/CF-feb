import os

bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
workers = 1          # SSE requires sticky connections; 1 worker avoids file-not-found across workers
threads = 4          # Handle concurrent requests within the single worker
timeout = 0          # DISABLE timeout — SSE keeps connection alive; gunicorn must not kill it
graceful_timeout = 30
worker_class = "gthread"
keepalive = 5

