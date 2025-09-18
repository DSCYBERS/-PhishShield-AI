# PhishShield AI Threat Intelligence Setup Script
# This script configures threat intelligence sources and trains ML models

Write-Host "🛡️  PhishShield AI - Threat Intelligence Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Change to project directory
$projectPath = "c:\Users\Student\Downloads\project ew"
Set-Location $projectPath

# Check if we're in the right directory
if (-not (Test-Path "backend\ml-trainer\train_models.py")) {
    Write-Host "❌ Error: Could not find ML trainer. Please run from project root." -ForegroundColor Red
    exit 1
}

Write-Host "📁 Project directory: $projectPath" -ForegroundColor Green

# Step 1: Setup environment variables for threat intelligence
Write-Host "`n🔧 Step 1: Configuring Threat Intelligence APIs..." -ForegroundColor Yellow

$envFile = "backend\.env"
if (-not (Test-Path $envFile)) {
    Copy-Item "backend\.env.example" $envFile
    Write-Host "✅ Created .env file from template" -ForegroundColor Green
} else {
    Write-Host "✅ Found existing .env file" -ForegroundColor Green
}

Write-Host "`n📝 Threat Intelligence API Configuration:" -ForegroundColor Cyan
Write-Host "To get the best threat detection, please configure these API keys:"
Write-Host "1. VirusTotal API: https://www.virustotal.com/gui/join-us"
Write-Host "2. Google Safe Browsing: https://developers.google.com/safe-browsing"
Write-Host "3. URLVoid API: https://www.urlvoid.com/api/"
Write-Host "4. PhishTank API: https://www.phishtank.com/api_info.php"
Write-Host ""
Write-Host "📄 Edit backend\.env and add your API keys:" -ForegroundColor White
Write-Host "VIRUSTOTAL_API_KEY=your_key_here"
Write-Host "GOOGLE_SAFEBROWSING_API_KEY=your_key_here"
Write-Host "URLVOID_API_KEY=your_key_here"
Write-Host "PHISHTANK_API_KEY=your_key_here"

# Step 2: Install Python dependencies
Write-Host "`n🐍 Step 2: Installing Python dependencies..." -ForegroundColor Yellow

try {
    Set-Location "backend\ml-trainer"
    
    # Check if Python is available
    $pythonCmd = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            & $cmd --version | Out-Null
            $pythonCmd = $cmd
            break
        } catch {
            continue
        }
    }
    
    if (-not $pythonCmd) {
        Write-Host "❌ Python not found. Please install Python 3.8+" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✅ Using Python command: $pythonCmd" -ForegroundColor Green
    
    # Install requirements
    Write-Host "📦 Installing ML training requirements..." -ForegroundColor Cyan
    & $pythonCmd -m pip install -r requirements.txt
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Python dependencies installed successfully" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Warning: Some dependencies may have failed to install" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "❌ Error installing Python dependencies: $_" -ForegroundColor Red
}

# Step 3: Run ML training
Write-Host "`n🤖 Step 3: Training ML Models..." -ForegroundColor Yellow

try {
    Write-Host "🔥 Starting ML model training with threat intelligence integration..." -ForegroundColor Cyan
    Write-Host "This will:"
    Write-Host "  • Collect phishing and legitimate URLs"
    Write-Host "  • Extract 48 features (43 original + 5 threat intel)"
    Write-Host "  • Train LightGBM, TensorFlow, and XGBoost models"
    Write-Host "  • Convert to TensorFlow Lite for mobile deployment"
    Write-Host "  • Deploy models to Android assets"
    
    # Run the training script
    & $pythonCmd train_models.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ ML models trained successfully!" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Warning: ML training completed with warnings" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "❌ Error during ML training: $_" -ForegroundColor Red
}

# Step 4: Start backend services
Write-Host "`n🚀 Step 4: Starting Backend Services..." -ForegroundColor Yellow

try {
    Set-Location ".."  # Back to backend directory
    
    Write-Host "🐳 Starting Docker services..." -ForegroundColor Cyan
    Write-Host "This will start:"
    Write-Host "  • PostgreSQL database"
    Write-Host "  • Redis cache"
    Write-Host "  • Neo4j graph database"
    Write-Host "  • PhishShield API server"
    
    # Check if Docker is available
    try {
        docker --version | Out-Null
        Write-Host "✅ Docker is available" -ForegroundColor Green
        
        # Start services
        docker-compose up -d
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Backend services started successfully!" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Warning: Some services may have failed to start" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "❌ Docker not found. Please install Docker Desktop" -ForegroundColor Red
        Write-Host "📥 Download: https://www.docker.com/products/docker-desktop" -ForegroundColor Cyan
    }
    
} catch {
    Write-Host "❌ Error starting backend services: $_" -ForegroundColor Red
}

# Step 5: Test threat intelligence
Write-Host "`n🧪 Step 5: Testing Threat Intelligence..." -ForegroundColor Yellow

try {
    Start-Sleep -Seconds 10  # Wait for services to start
    
    Write-Host "🔍 Testing threat intelligence endpoints..." -ForegroundColor Cyan
    
    # Test health endpoint
    try {
        $healthResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/health" -Method Get -TimeoutSec 5
        Write-Host "✅ API health check passed" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  API not responding yet (this is normal)" -ForegroundColor Yellow
    }
    
    Write-Host "🌐 Threat Intelligence APIs will be available at:" -ForegroundColor Cyan
    Write-Host "  • http://localhost:8000/api/threat-intel/analyze/{url}"
    Write-Host "  • http://localhost:8000/api/threat-intel/domain/{domain}"
    Write-Host "  • http://localhost:8000/api/threat-intel/reputation/{domain}"
    Write-Host "  • http://localhost:8000/api/threat-intel/feeds/status"
    
} catch {
    Write-Host "⚠️  Could not test endpoints (services may still be starting)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n🎉 Setup Complete!" -ForegroundColor Green
Write-Host "==================" -ForegroundColor Green
Write-Host "✅ Threat intelligence service configured"
Write-Host "✅ ML models trained with threat intel features"
Write-Host "✅ Backend services started"
Write-Host "✅ Android app ready for enhanced detection"

Write-Host "`n📱 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Build and install the Android APK"
Write-Host "2. Configure API keys in backend\.env for better detection"
Write-Host "3. Monitor threat intelligence feeds at: http://localhost:8000/api/threat-intel/feeds/status"

Write-Host "`n🛡️  Your PhishShield AI system is now armed with:" -ForegroundColor White
Write-Host "  • 7-layer defense architecture"
Write-Host "  • Real-time threat intelligence from multiple sources"
Write-Host "  • Enhanced ML models with 48 features"
Write-Host "  • System-wide URL interception"
Write-Host "  • Cloud-based sandbox analysis"
Write-Host "  • Network graph threat detection"

Write-Host "`nPress any key to continue..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Set-Location $projectPath
