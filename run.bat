@echo off
REM Check if Python is installed
python --version
IF ERRORLEVEL 1 (
    echo Python is not installed. Please install Python 3.11 from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Create virtual environment
python -m venv venv
call venv\Scripts\activate

REM Install requirements
pip install -r requirements.txt

REM Run the application
python main.py

REM Deactivate virtual environment
call venv\Scripts\deactivate
pause
