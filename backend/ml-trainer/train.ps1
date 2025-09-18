# PhishShield AI - ML Model Training Script (PowerShell)
Write-Host "==========================================" -ForegroundColor Green
Write-Host "PhishShield AI - ML Model Training" -ForegroundColor Green  
Write-Host "==========================================" -ForegroundColor Green

# Create necessary directories
New-Item -ItemType Directory -Force -Path models
New-Item -ItemType Directory -Force -Path training_data
New-Item -ItemType Directory -Force -Path results
New-Item -ItemType Directory -Force -Path datasets

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Docker is not running. Please start Docker first." -ForegroundColor Red
    exit 1
}

# Create sample dataset if it doesn't exist
if (!(Test-Path "datasets/phishing_urls.txt")) {
    Write-Host "Creating sample phishing dataset..." -ForegroundColor Yellow
    
    $samplePhishingUrls = @"
http://paypal-security-update.fake-domain.com/login
https://amazon-verify-account.suspicious-site.org/signin
http://google-security-alert.malicious-domain.net/verify
https://microsoft-account-suspended.phishing-site.com/login
http://bank-of-america-verify.fake-bank.org/signin
https://apple-id-locked.phishing-domain.com/unlock
http://netflix-payment-failed.scam-site.net/update
https://facebook-security-check.malicious.org/verify
http://instagram-account-review.fake.com/login
https://linkedin-profile-restricted.scam.net/verify
"@
    
    $samplePhishingUrls | Out-File -FilePath "datasets/phishing_urls.txt" -Encoding UTF8
}

Write-Host "Starting ML model training..." -ForegroundColor Cyan

# Build the ML training Docker container
Write-Host "Building ML training container..." -ForegroundColor Yellow
docker build -t phishshield-ml-trainer .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker build failed" -ForegroundColor Red
    exit 1
}

# Run the training
Write-Host "Running model training..." -ForegroundColor Yellow
docker run --rm `
    -v "${PWD}/models:/app/models" `
    -v "${PWD}/training_data:/app/training_data" `
    -v "${PWD}/results:/app/results" `
    -v "${PWD}/datasets:/app/datasets" `
    --name phishshield-training `
    phishshield-ml-trainer

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Training failed" -ForegroundColor Red
    exit 1
}

Write-Host "Training completed!" -ForegroundColor Green

# Check if models were created
if (Test-Path "models/phishing_detector.tflite") {
    Write-Host "✅ TensorFlow Lite model created successfully" -ForegroundColor Green
    Get-ChildItem "models/phishing_detector.tflite" | Format-Table Name, Length, LastWriteTime
} else {
    Write-Host "❌ TensorFlow Lite model not found" -ForegroundColor Red
}

if (Test-Path "models/lightgbm_phishing_detector.txt") {
    Write-Host "✅ LightGBM model created successfully" -ForegroundColor Green
    Get-ChildItem "models/lightgbm_phishing_detector.txt" | Format-Table Name, Length, LastWriteTime
} else {
    Write-Host "❌ LightGBM model not found" -ForegroundColor Red
}

# Copy models to Android assets
$androidAssetsDir = "../app/src/main/assets/models"
if (Test-Path $androidAssetsDir) {
    Write-Host "Copying models to Android assets..." -ForegroundColor Yellow
    
    if (Test-Path "models/phishing_detector.tflite") {
        Copy-Item "models/phishing_detector.tflite" "$androidAssetsDir/"
        Write-Host "✅ TensorFlow Lite model copied to Android assets" -ForegroundColor Green
    }
    
    if (Test-Path "models/lightgbm_mobile.txt") {
        Copy-Item "models/lightgbm_mobile.txt" "$androidAssetsDir/"
        Write-Host "✅ LightGBM model copied to Android assets" -ForegroundColor Green
    }
} else {
    Write-Host "Android assets directory not found. Creating it..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $androidAssetsDir
    
    if (Test-Path "models/phishing_detector.tflite") {
        Copy-Item "models/phishing_detector.tflite" "$androidAssetsDir/"
        Write-Host "✅ TensorFlow Lite model copied to Android assets" -ForegroundColor Green
    }
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host "ML Training Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

# Show training results if available
if (Test-Path "results/training_report.json") {
    Write-Host "Training Results:" -ForegroundColor Cyan
    
    try {
        $report = Get-Content "results/training_report.json" | ConvertFrom-Json
        
        Write-Host "Training Date: $($report.training_date)"
        Write-Host "`nModel Performance:"
        
        foreach ($model in $report.model_performance.PSObject.Properties) {
            $metrics = $model.Value
            Write-Host "  $($model.Name):"
            Write-Host "    AUC Score: $($metrics.auc_score.ToString('F4'))"
            
            if ($metrics.classification_report.'1') {
                $cr = $metrics.classification_report.'1'
                Write-Host "    Precision: $($cr.precision.ToString('F4'))"
                Write-Host "    Recall: $($cr.recall.ToString('F4'))"
                Write-Host "    F1-Score: $($cr.'f1-score'.ToString('F4'))"
            }
        }
        
        Write-Host "`nRecommendations:"
        foreach ($rec in $report.recommendations) {
            Write-Host "  - $rec"
        }
    } catch {
        Write-Host "Could not parse training report" -ForegroundColor Red
    }
}
