@echo off
echo ========================================
echo PhishShield AI Backend Demo Setup
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo ✅ Python is installed
    python --version
    goto :setup_backend
)

py --version >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo ✅ Python is installed via py launcher
    py --version
    goto :setup_backend
)

echo ❌ Python not found!
echo.
echo 📥 Please install Python from: https://python.org/downloads/
echo    Choose "Add Python to PATH" during installation
echo.
echo 💡 Alternative: Install from Microsoft Store
echo    search "Python 3.11" in Microsoft Store
echo.
pause
exit /b 1

:setup_backend
echo.
echo 🚀 Setting up PhishShield AI Backend...
echo.

REM Navigate to backend directory
cd backend

REM Install required packages
echo Installing dependencies...
pip install fastapi uvicorn aiohttp redis python-dotenv requests

REM Check if installation succeeded
if %ERRORLEVEL% == 0 (
    echo ✅ Dependencies installed successfully
) else (
    echo ❌ Failed to install dependencies
    echo 💡 Try: python -m pip install --upgrade pip
    pause
    exit /b 1
)

echo.
echo 🌟 Backend setup complete!
echo.
echo =======================================
echo Starting PhishShield AI Server...
echo =======================================
echo.
echo 🌐 Server will be available at:
echo    http://localhost:8000
echo    http://localhost:8000/docs (API Documentation)
echo.
echo 🛑 Press Ctrl+C to stop the server
echo.

REM Start the server
python start.py

pause
