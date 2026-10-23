#!/bin/sh
# Home network over HTTPS (needed for installing on iPhone / iPad).
# Certs/ next to app.py: cert.pem, key.pem and the mkcert root rootCA.pem.
cd "$(dirname "$0")/../.." && exec venv/bin/python app.py --host 0.0.0.0 \
    --cert Certs/cert.pem --key Certs/key.pem --ca-file Certs/rootCA.pem "$@"
