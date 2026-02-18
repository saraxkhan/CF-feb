import os

bind             = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
workers          = 1       # single worker so in-memory _jobs dict is shared
threads          = 8       # handle concurrent SSE polls + POST requests
timeout          = 120     # individual request timeout (SSE polls are short)
graceful_timeout = 30
worker_class     = "gthread"
keepalive        = 5
