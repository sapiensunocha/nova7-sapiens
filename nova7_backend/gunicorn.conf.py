# gunicorn.conf.py
timeout = 60  # Increase timeout to 60 seconds
workers = 2   # Use 2 workers to stay within Render free-tier memory limits
max_requests = 1000  # Restart workers after 1000 requests to prevent memory leaks
max_requests_jitter = 100
loglevel = 'debug'  # Enable debug logging for Gunicorn