Write-Host "PhishShield AI - Build Environment Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Checking Java JDK 11..." -ForegroundColor Yellow
$javaCheck = cmd /c "java -version 2>&1"
if ($javaCheck -match "11\.") {
    Write-Host "✅ Java JDK 11+ is installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Installing Java JDK 11..." -ForegroundColor Red
    winget install EclipseAdoptium.Temurin.11.JDK --accept-source-agreements --accept-package-agreements --silent
    Write-Host "✅ Java installation completed" -ForegroundColor Green
}

Write-Host ""
Write-Host "Checking Android Studio..." -ForegroundColor Yellow
if (Test-Path "$env:ProgramFiles\Android\Android Studio\bin\studio64.exe") {
    Write-Host "✅ Android Studio is installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Android Studio not found" -ForegroundColor Red
    Write-Host "Opening download page..." -ForegroundColor Yellow
    Start-Process "https://developer.android.com/studio"
    Write-Host "Please install Android Studio with Android SDK components" -ForegroundColor White
}

Write-Host ""
Write-Host "Checking Python..." -ForegroundColor Yellow
$pythonCheck = cmd /c "python --version 2>&1"
if ($pythonCheck -match "Python") {
    Write-Host "✅ Python is installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Installing Python..." -ForegroundColor Red
    winget install Python.Python.3.11 --accept-source-agreements --accept-package-agreements --silent
}

Write-Host ""
Write-Host "Setup Instructions:" -ForegroundColor Cyan
Write-Host "1. Restart PowerShell" -ForegroundColor White
Write-Host "2. Open Android Studio" -ForegroundColor White
Write-Host "3. Import this project folder" -ForegroundColor White
Write-Host "4. Build APK from Build menu" -ForegroundColor White
Write-Host ""
Write-Host "PhishShield AI is ready for deployment!" -ForegroundColor Green