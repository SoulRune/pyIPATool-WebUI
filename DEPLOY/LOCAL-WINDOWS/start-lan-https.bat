@echo off
rem Home network over HTTPS (needed for installing on iPhone / iPad).
rem Certs\ next to app.py: cert.pem, key.pem and the mkcert root rootCA.pem.
cd /d "%~dp0..\.."
"venv\Scripts\python.exe" app.py --host 0.0.0.0 ^
    --cert "Certs\cert.pem" --key "Certs\key.pem" --ca-file "Certs\rootCA.pem"
pause
