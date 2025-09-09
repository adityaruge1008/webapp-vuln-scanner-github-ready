@echo off
REM Quick run script for Windows (assumes venv has been created)
if not exist venv\Scripts\activate (
  echo Virtual environment not found. Creating venv...
  python -m venv venv
  call venv\Scripts\activate
  pip install -r requirements.txt
) else (
  call venv\Scripts\activate
)
python app.py
