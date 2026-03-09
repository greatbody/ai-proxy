@echo off
setlocal

:: Activate virtual environment if it exists
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)

:: Load .env file if it exists
if exist .env (
    for /f "tokens=*" %%i in ('findstr /v "^#" .env') do set %%i
)

:: Run webui.py
python webui.py
