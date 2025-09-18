# PhishShield AI - Python Setup Script
# This script will install Python and set up the backend

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PhishShield AI - Python Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is already installed
try {
    $pythonVersion = python --version 2>$null
    if ($pythonVersion) {
        Write-Host "✅ Python is already installed: $pythonVersion" -ForegroundColor Green
        Write-Host ""
        Write-Host "🚀 Proceeding to backend setup..." -ForegroundColor Yellow
        & ".\start-demo.bat"
        exit 0
    }
} catch {
    # Python not found, continue with installation
}

try {
    $pyVersion = py --version 2>$null
    if ($pyVersion) {
        Write-Host "✅ Python is already installed via py launcher: $pyVersion" -ForegroundColor Green
        Write-Host ""
        Write-Host "🚀 Proceeding to backend setup..." -ForegroundColor Yellow
        & ".\start-demo.bat"
        exit 0
    }
} catch {
    # Python not found, continue with installation
}

Write-Host "❌ Python not found! Installing Python..." -ForegroundColor Red
Write-Host ""

# Try to install Python using winget
Write-Host "📦 Attempting to install Python using Windows Package Manager..." -ForegroundColor Yellow
try {
    $result = winget install Python.Python.3.11 --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Python installed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "🔄 Refreshing environment variables..." -ForegroundColor Yellow
        
        # Refresh PATH environment variable
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        Write-Host "Environment refreshed!" -ForegroundColor Green
        Write-Host ""
        Write-Host "🚀 Starting PhishShield AI backend..." -ForegroundColor Yellow
        & ".\start-demo.bat"
        exit 0
    }
} catch {
    Write-Host "⚠️ Winget installation failed. Trying alternative method..." -ForegroundColor Yellow
}

# Alternative: Try chocolatey if available
Write-Host "📦 Attempting to install Python using Chocolatey..." -ForegroundColor Yellow
try {
    choco install python3 -y
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Python installed successfully via Chocolatey!" -ForegroundColor Green
        refreshenv
        & ".\start-demo.bat"
        exit 0
    }
} catch {
    Write-Host "⚠️ Chocolatey not available or failed." -ForegroundColor Yellow
}

# Manual installation instructions
Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "MANUAL INSTALLATION REQUIRED" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "Please install Python manually:" -ForegroundColor Yellow
Write-Host ""
Write-Host "🌐 Option 1: Download from official website" -ForegroundColor Cyan
Write-Host "   1. Go to: https://python.org/downloads/" -ForegroundColor White
Write-Host "   2. Download Python 3.11 or 3.12" -ForegroundColor White
Write-Host "   3. ⚠️  IMPORTANT: Check 'Add Python to PATH' during installation" -ForegroundColor Red
Write-Host "   4. Run this script again after installation" -ForegroundColor White
Write-Host ""
Write-Host "🏪 Option 2: Install from Microsoft Store" -ForegroundColor Cyan
Write-Host "   1. Open Microsoft Store" -ForegroundColor White
Write-Host "   2. Search for 'Python 3.11'" -ForegroundColor White
Write-Host "   3. Install and run this script again" -ForegroundColor White
Write-Host ""
Write-Host "🔧 Option 3: Use PowerShell (Administrator)" -ForegroundColor Cyan
Write-Host "   Run PowerShell as Administrator and execute:" -ForegroundColor White
Write-Host "   winget install Python.Python.3.11" -ForegroundColor Gray
Write-Host ""

Read-Host "Press Enter to exit..."
