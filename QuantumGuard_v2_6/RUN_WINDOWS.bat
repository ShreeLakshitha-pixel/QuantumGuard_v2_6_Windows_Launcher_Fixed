@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title QuantumGuard v2.6 - Launcher

REM Keep a log beside this script so startup errors are not lost.
set "LOG=%~dp0STARTUP_LOG.txt"
echo ================================================== > "%LOG%"
echo QuantumGuard v2.6 startup - %DATE% %TIME%>> "%LOG%"
echo Project folder: %CD%>> "%LOG%"
echo ==================================================>> "%LOG%"

echo.
echo ==========================================
echo   QuantumGuard v2.6 - Startup
echo ==========================================
echo Project folder: %CD%
echo Startup log: %LOG%
echo.

REM Find a usable Python 3 installation.
set "PYEXE="
where py >nul 2>nul
if not errorlevel 1 (
    py -3 --version >> "%LOG%" 2>&1
    if not errorlevel 1 set "PYEXE=py -3"
)
if not defined PYEXE (
    where python >nul 2>nul
    if not errorlevel 1 (
        python --version >> "%LOG%" 2>&1
        if not errorlevel 1 set "PYEXE=python"
    )
)
if not defined PYEXE goto no_python

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    echo Creating virtual environment...>> "%LOG%"
    %PYEXE% -m venv .venv >> "%LOG%" 2>&1
    if errorlevel 1 goto venv_failed
)

set "VENV_PY=%~dp0.venv\Scripts\python.exe"
if not exist "%VENV_PY%" goto venv_failed

echo Checking/installing dependencies (first run may take a few minutes)...
echo Installing dependencies...>> "%LOG%"
"%VENV_PY%" -m pip install -r requirements.txt >> "%LOG%" 2>&1
if errorlevel 1 goto install_failed

echo.
echo Starting QuantumGuard at http://127.0.0.1:8000
echo Keep this window open while using the app.
echo Log file: %LOG%
echo.
echo Starting Flask app...>> "%LOG%"
"%VENV_PY%" app.py >> "%LOG%" 2>&1
if errorlevel 1 goto app_failed

goto finished

:no_python
echo ERROR: Python 3 was not found.
echo Install Python 3.10 or newer from https://www.python.org/downloads/windows/
echo During installation, tick "Add python.exe to PATH", then reopen this folder.
echo Python not found.>> "%LOG%"
goto failed

:venv_failed
echo ERROR: Could not create the virtual environment.
echo Check the Python installation and folder permissions.
echo Virtual environment creation failed.>> "%LOG%"
goto failed

:install_failed
echo ERROR: Dependency installation failed.
echo Check your internet connection. Details are in STARTUP_LOG.txt.
echo Dependency installation failed.>> "%LOG%"
goto failed

:app_failed
echo ERROR: QuantumGuard stopped with an error.
echo Read STARTUP_LOG.txt in this folder and share its last 30 lines for help.
echo App exited with error.>> "%LOG%"
goto failed

:failed
echo.
echo The window will stay open so you can read this message.
echo See STARTUP_LOG.txt for technical details.
pause
exit /b 1

:finished
echo.
echo QuantumGuard has stopped.
pause
endlocal
