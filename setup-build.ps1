# PhishShield AI - Build Environment Setup
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PhishShield AI - Build Environment Setup" -ForegroundColor Cyan  
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Java
Write-Host "🔍 Checking Java JDK 11..." -ForegroundColor Yellow
$javaInstalled = $false
try {
    $javaOutput = & java -version 2>&1
    $javaVersionString = $javaOutput | Out-String
    if ($javaVersionString -match "11\.") {
        Write-Host "✅ Java JDK 11+ is already installed!" -ForegroundColor Green
        $javaInstalled = $true
    }
}
catch {
    Write-Host "❌ Java JDK 11+ not found" -ForegroundColor Red
}

if (-not $javaInstalled) {
    Write-Host "📦 Installing Java JDK 11 via winget..." -ForegroundColor Yellow
    winget install EclipseAdoptium.Temurin.11.JDK --accept-source-agreements --accept-package-agreements --silent
    Write-Host "✅ Java installation initiated" -ForegroundColor Green
}

Write-Host ""

# Check Android Studio
Write-Host "🔍 Checking Android Studio..." -ForegroundColor Yellow
$studioPath1 = Join-Path $env:ProgramFiles "Android\Android Studio\bin\studio64.exe"
$studioPath2 = Join-Path $env:LOCALAPPDATA "Android\Android Studio\bin\studio64.exe"

if ((Test-Path $studioPath1) -or (Test-Path $studioPath2)) {
    Write-Host "✅ Android Studio is installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Android Studio not found" -ForegroundColor Red
    Write-Host "🌐 Opening Android Studio download page..." -ForegroundColor Yellow
    Start-Process "https://developer.android.com/studio"
    Write-Host ""
    Write-Host "📋 Install Android Studio with these components:" -ForegroundColor Yellow
    Write-Host "   ✓ Android SDK" -ForegroundColor Cyan
    Write-Host "   ✓ Android SDK Platform-Tools" -ForegroundColor Cyan  
    Write-Host "   ✓ Android SDK Build-Tools" -ForegroundColor Cyan
}

Write-Host ""

# Check Python
Write-Host "🔍 Checking Python..." -ForegroundColor Yellow
try {
    $pythonOutput = & python --version 2>&1
    if ($pythonOutput) {
        Write-Host "✅ Python installed: $pythonOutput" -ForegroundColor Green
    }
}
catch {
    Write-Host "❌ Python not found, installing..." -ForegroundColor Red
    winget install Python.Python.3.11 --accept-source-agreements --accept-package-agreements --silent
}

Write-Host ""
Write-Host "🎯 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Restart PowerShell to refresh PATH variables" -ForegroundColor White
Write-Host "2. Open Android Studio and import this project folder" -ForegroundColor White
Write-Host "3. Build APK: Build menu > Build Bundle(s) / APK(s) > Build APK(s)" -ForegroundColor White
Write-Host "4. Test backend demo: python simple-demo.py" -ForegroundColor White
Write-Host ""

Write-Host "🏆 PhishShield AI Setup Complete!" -ForegroundColor Green
Write-Host "Your advanced phishing protection system is ready!" -ForegroundColor Cyan
Write-Host ""