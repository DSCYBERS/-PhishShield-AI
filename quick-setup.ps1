# PhishShield AI - Simple Build Environment Setup
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PhishShield AI - Build Environment Setup" -ForegroundColor Cyan  
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "🔍 Checking Java JDK 11..." -ForegroundColor Yellow
try {
    $javaCheck = java -version 2>&1
    if ($javaCheck -match "11\.") {
        Write-Host "✅ Java JDK 11+ is already installed!" -ForegroundColor Green
    } else {
        Write-Host "❌ Java JDK 11+ required but different version found" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Java JDK 11+ not found. Installing..." -ForegroundColor Red
    Write-Host "📦 Installing Java JDK 11 via winget..." -ForegroundColor Yellow
    winget install EclipseAdoptium.Temurin.11.JDK --accept-source-agreements --accept-package-agreements --silent
}

Write-Host ""
Write-Host "🔍 Checking Android Studio..." -ForegroundColor Yellow
$studioFound = $false
if (Test-Path "${env:ProgramFiles}\Android\Android Studio\bin\studio64.exe") {
    $studioFound = $true
}
if (Test-Path "${env:LOCALAPPDATA}\Android\Android Studio\bin\studio64.exe") {
    $studioFound = $true
}

if ($studioFound) {
    Write-Host "✅ Android Studio is installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Android Studio not found" -ForegroundColor Red
    Write-Host "🌐 Opening Android Studio download page..." -ForegroundColor Yellow
    Start-Process "https://developer.android.com/studio"
    Write-Host ""
    Write-Host "📋 Please install Android Studio with these components:" -ForegroundColor Yellow
    Write-Host "   ✓ Android SDK" -ForegroundColor Cyan
    Write-Host "   ✓ Android SDK Platform-Tools" -ForegroundColor Cyan  
    Write-Host "   ✓ Android SDK Build-Tools" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🔍 Checking Python..." -ForegroundColor Yellow
try {
    $pythonCheck = python --version 2>$null
    if ($pythonCheck) {
        Write-Host "✅ Python installed: $pythonCheck" -ForegroundColor Green
    } else {
        Write-Host "❌ Python not found" -ForegroundColor Red
        winget install Python.Python.3.11 --accept-source-agreements --accept-package-agreements --silent
    }
} catch {
    Write-Host "❌ Python not found" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎯 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Restart PowerShell to refresh PATH" -ForegroundColor White
Write-Host "2. Open Android Studio and import this project" -ForegroundColor White
Write-Host "3. Build APK: Build > Build Bundle(s) / APK(s) > Build APK(s)" -ForegroundColor White
Write-Host "4. Test backend: python simple-demo.py" -ForegroundColor White
Write-Host ""

Write-Host "🏆 PhishShield AI Setup Complete!" -ForegroundColor Green
Write-Host "Ready for deployment and testing!" -ForegroundColor Cyan