import os

bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
workers = 2
threads = 2
timeout = 300        # 5 minutes — certificates take time on free tier
graceful_timeout = 60
worker_class = "sync"
