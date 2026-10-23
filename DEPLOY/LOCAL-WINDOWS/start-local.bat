@echo off
rem Only this PC: http://127.0.0.1:5002
cd /d "%~dp0..\.."
"venv\Scripts\python.exe" app.py
pause
