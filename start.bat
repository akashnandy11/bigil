@echo off
cd /d "%~dp0"
echo Starting BIGIL Forensic Platform...
if not exist "venv\Scripts\python.exe" (
  echo Creating virtual environment...
  python -m venv venv
  venv\Scripts\pip install -r requirements.txt
)
venv\Scripts\python run.py
pause
