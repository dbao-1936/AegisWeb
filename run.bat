@echo off
title AegisWeb - Web Security Scanner & Metasploit Advisory
echo ==============================================================
echo   AEGISWEB SCANNER - PHONG THU & DANH GIA AN TOAN WEB
echo ==============================================================
cd /d "%~dp0"

if exist "%~dp0venv\Scripts\python.exe" (
    echo [*] Tim thay moi truong venv. Dang khoi dong...
    "%~dp0venv\Scripts\python.exe" run.py
) else if exist "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" (
    echo [*] Tim thay Python 3.9 tai Programs. Dang khoi dong...
    "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" run.py
) else (
    echo [*] Dang khoi dong voi python he thong...
    python run.py
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Da xay ra loi khi chay ung dung.
    pause
)
