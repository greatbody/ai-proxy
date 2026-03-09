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

:: Run mitmdump
mitmdump -s llm_capture_addon.py --listen-host 127.0.0.1 --listen-port 8080 --set block_global=false
