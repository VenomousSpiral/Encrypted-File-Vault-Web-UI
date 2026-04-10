#!/usr/bin/env python3
"""Entry point for the Encrypted Vault server."""

from app import app, create_app
import config

create_app()

if __name__ == '__main__':
    print("\n  Encrypted Vault")
    print("  ───────────────────────────────────")
    print(f"  Running on http://{config.HOST}:{config.PORT}")
    print("  Press Ctrl+C to stop\n")
    app.run(host=config.HOST, port=config.PORT,
            debug=config.DEBUG, threaded=True)
