"""Code-Shield entry point.

Run with: python app.py  (or: uvicorn app:app)
"""

import os

import uvicorn

from server.main import create_app

app = create_app()


if __name__ == "__main__":
    reload_enabled = os.getenv("RELOAD", "0") == "1"
    uvicorn.run(
        "app:app" if reload_enabled else app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=reload_enabled,
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        log_config=None,
    )
