#!/bin/sh
# Only this computer: http://127.0.0.1:5002
cd "$(dirname "$0")/../.." && exec venv/bin/python app.py "$@"
