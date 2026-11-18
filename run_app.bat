@echo off
title NETGUARD AI - SOC Console
color 0B
cls

echo ===================================================================
echo                    NETGUARD AI - SOC CONSOLE
echo      Autonomous Machine Learning Network Threat Detection
echo ===================================================================
echo.

set "PATH=%LOCALAPPDATA%\Programs\Python\Python311;%LOCALAPPDATA%\Programs\Python\Python311\Scripts;%PATH%"

echo Initializing workspace at D:\NIDS_ML_Project ...
cd /d "D:\NIDS_ML_Project"

echo Checking Python runtime environment...
python --version
if errorlevel 1 (
    echo [ERROR] Python was not found on your system.
    pause
    exit /b 1
)

echo.
echo Starting NETGUARD AI SOC Engine...
echo Dashboard URL: http://localhost:8501
echo Opening browser automatically...
echo ===================================================================
echo   Keep this Command Prompt window open while using NETGUARD AI.
echo   Press Ctrl+C to stop the server when finished.
echo ===================================================================
echo.

start "" http://localhost:8501

python -m streamlit run app/app.py --server.port 8501 --server.headless false

if errorlevel 1 (
    echo.
    echo Streamlit exited with error code %ERRORLEVEL%.
    pause
)

pause
