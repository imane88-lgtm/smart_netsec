# backend/utils/logger.py
import logging
import os

LOG_DIR  = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_fmt = logging.Formatter(
    "%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_handlers_added = set()


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if name not in _handlers_added:
        logger.setLevel(logging.DEBUG)
        # Console
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(_fmt)
        logger.addHandler(ch)
        # Fichier
        try:
            fh = logging.FileHandler(os.path.join(LOG_DIR, "netsec.log"), encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(_fmt)
            logger.addHandler(fh)
        except Exception:
            pass
        logger.propagate = False
        _handlers_added.add(name)
    return logger
