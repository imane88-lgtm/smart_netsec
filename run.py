#!/usr/bin/env python3
# run.py — Smart NetSec SOC Platform v3.0
# HTTPS + Hostname custom + Login obligatoire
import os, sys, ssl

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from backend.app import create_app

app = create_app()

# ── Affichage démarrage ─────────────────────────────────
print("""
╔══════════════════════════════════════════════════════╗
║       Smart NetSec SOC Platform v3.0                ║
║                                                      ║
║  🔒 HTTPS  : https://soc.local:5443                 ║
║  🔒 HTTPS  : https://192.168.216.143:5443           ║
║  📡 HTTP   : http://0.0.0.0:5000  (redirect)       ║
║                                                      ║
║  👤 admin  : Admin@2025!                            ║
║  👤 user   : User@2025!                             ║
╚══════════════════════════════════════════════════════╝
""")

# ── Vérifier certificats SSL ────────────────────────────
SSL_CERT = os.path.join(ROOT, "ssl", "cert.pem")
SSL_KEY  = os.path.join(ROOT, "ssl", "key.pem")
USE_HTTPS = os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY)

if USE_HTTPS:
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(SSL_CERT, SSL_KEY)
    print(f"✅ SSL activé — cert: {SSL_CERT}")
    # Lancer en HTTPS sur port 5443
    app.run(
        host="0.0.0.0",
        port=5443,
        ssl_context=(SSL_CERT, SSL_KEY),
        debug=app.config.get("DEBUG", False),
        use_reloader=False,
    )
else:
    print("⚠️  SSL non disponible — mode HTTP")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=app.config.get("DEBUG", False),
        use_reloader=False,
    )
