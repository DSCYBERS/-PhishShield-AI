# PhishShield AI - PowerShell Build Environment Setup
# Advanced setup script with automatic detection and configuration

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PhishShield AI - Build Environment Setup" -ForegroundColor Cyan  
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to check if Java is installed
function Test-JavaInstallation {
    try {
        $javaVersion = & java -version 2>&1
        if ($javaVersion -match "11\.") {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

# Function to check if Android Studio is installed
function Test-AndroidStudioInstallation {
    $studioPath1 = "${env:ProgramFiles}\Android\Android Studio\bin\studio64.exe"
    $studioPath2 = "${env:LOCALAPPDATA}\Android\Android Studio\bin\studio64.exe"
    
    return (Test-Path $studioPath1) -or (Test-Path $studioPath2)
}

Write-Host "🔍 Checking current environment..." -ForegroundColor Yellow
Write-Host ""

# Check Java
$javaInstalled = Test-JavaInstallation
if ($javaInstalled) {
    Write-Host "✅ Java JDK 11+ is already installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Java JDK 11+ not found. Installing..." -ForegroundColor Red
    
    Write-Host "📦 Installing Java JDK 11 via winget..." -ForegroundColor Yellow
    try {
        $result = winget install EclipseAdoptium.Temurin.11.JDK --accept-source-agreements --accept-package-agreements --silent
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Java JDK 11 installed successfully!" -ForegroundColor Green
            
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
        } else {
            Write-Host "⚠️ Winget installation failed. Manual installation required." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Please download Java JDK 11 from:" -ForegroundColor White
            Write-Host "https://adoptium.net/temurin/releases/?version=11" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Choose: OpenJDK 11 LTS > Windows x64 > JDK > .msi installer" -ForegroundColor White
            Write-Host "⚠️ IMPORTANT: Check 'Set JAVA_HOME variable' during installation" -ForegroundColor Red
            Write-Host ""
            Read-Host "Press Enter after installing Java..."
        }
    } catch {
        Write-Host "❌ Failed to install Java automatically." -ForegroundColor Red
        Write-Host "Please install manually from: https://adoptium.net/temurin/releases/?version=11" -ForegroundColor Yellow
    }
}

Write-Host ""

# Check Android Studio
$androidStudioInstalled = Test-AndroidStudioInstallation
if ($androidStudioInstalled) {
    Write-Host "✅ Android Studio is already installed!" -ForegroundColor Green
} else {
    Write-Host "❌ Android Studio not found. Opening download page..." -ForegroundColor Red
    
    Write-Host "🌐 Opening Android Studio download page..." -ForegroundColor Yellow
    Start-Process "https://developer.android.com/studio"
    
    Write-Host ""
    Write-Host "📋 Android Studio Installation Checklist:" -ForegroundColor Yellow
    Write-Host "1. Download Android Studio from the opened webpage" -ForegroundColor White
    Write-Host "2. Run the installer and follow the setup wizard" -ForegroundColor White
    Write-Host "3. During setup, ensure these components are installed:" -ForegroundColor White
    Write-Host "   ✓ Android SDK" -ForegroundColor Cyan
    Write-Host "   ✓ Android SDK Platform-Tools" -ForegroundColor Cyan
    Write-Host "   ✓ Android SDK Build-Tools" -ForegroundColor Cyan
    Write-Host "   ✓ Android Emulator (optional for testing)" -ForegroundColor Cyan
    Write-Host ""
    Read-Host "Press Enter after installing Android Studio..."
}

Write-Host ""
Write-Host "🔧 Setting up Python environment for backend demo..." -ForegroundColor Yellow

# Check Python
try {
    $pythonVersion = python --version 2>$null
    if ($pythonVersion) {
        Write-Host "✅ Python is already installed: $pythonVersion" -ForegroundColor Green
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "📦 Installing Python..." -ForegroundColor Yellow
    try {
        winget install Python.Python.3.11 --accept-source-agreements --accept-package-agreements --silent
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Python installed successfully!" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️ Please install Python manually from: https://python.org/downloads/" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "🎯 Final Setup Steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. 🔄 Restart your PowerShell/Command Prompt" -ForegroundColor White
Write-Host "2. ✅ Verify installations:" -ForegroundColor White
Write-Host "   - Run: java -version (should show Java 11)" -ForegroundColor Gray
Write-Host "   - Run: python --version (should show Python 3.x)" -ForegroundColor Gray
Write-Host ""
Write-Host "3. 🏗️ Build your PhishShield AI APK:" -ForegroundColor White
Write-Host "   - Open Android Studio" -ForegroundColor Gray
Write-Host "   - File > Open > Select your project folder" -ForegroundColor Gray
Write-Host "   - Build > Build APKs" -ForegroundColor Gray
Write-Host ""
Write-Host "4. 🚀 Test the backend demo:" -ForegroundColor White
Write-Host "   - Run: python simple-demo.py" -ForegroundColor Gray
Write-Host "   - Open: http://localhost:8080/demo.html" -ForegroundColor Gray
Write-Host ""

Write-Host "========================================" -ForegroundColor Green
Write-Host "🏆 PhishShield AI Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Your PhishShield AI features:" -ForegroundColor White
Write-Host "✅ Industry-leading 7-layer defense system" -ForegroundColor Green
Write-Host "✅ Advanced 48-feature ML detection engine" -ForegroundColor Green  
Write-Host "✅ Real-time URL blocking and analysis" -ForegroundColor Green
Write-Host "✅ Complete database and analytics system" -ForegroundColor Green
Write-Host "✅ Production-ready Android application" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 Ready for deployment and testing!" -ForegroundColor Cyan
Write-Host ""

Read-Host "Press Enter to continue..."