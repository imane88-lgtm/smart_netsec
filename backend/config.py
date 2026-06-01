# backend/config.py
import os


class Config:
    SECRET_KEY = os.environ.get("NETSEC_SECRET", "netsec-soc-secret-2025-v3")
    DEBUG      = os.environ.get("FLASK_DEBUG", "1") == "1"
    HOST       = os.environ.get("FLASK_HOST", "0.0.0.0")
    PORT       = int(os.environ.get("FLASK_PORT", 5000))


config = Config()
