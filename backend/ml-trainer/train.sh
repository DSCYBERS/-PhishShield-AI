#!/bin/bash

# PhishShield AI - ML Model Training Script
echo "=========================================="
echo "PhishShield AI - ML Model Training"
echo "=========================================="

# Create necessary directories
mkdir -p models
mkdir -p training_data
mkdir -p results
mkdir -p datasets

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker first."
    exit 1
fi

# Check if datasets exist
if [ ! -f "datasets/phishing_urls.txt" ]; then
    echo "Creating sample phishing dataset..."
    cat > datasets/phishing_urls.txt << EOF
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
EOF
fi

echo "Starting ML model training..."

# Build the ML training Docker container
echo "Building ML training container..."
docker build -t phishshield-ml-trainer .

# Run the training
echo "Running model training..."
docker run --rm \
    -v $(pwd)/models:/app/models \
    -v $(pwd)/training_data:/app/training_data \
    -v $(pwd)/results:/app/results \
    -v $(pwd)/datasets:/app/datasets \
    --name phishshield-training \
    phishshield-ml-trainer

echo "Training completed!"

# Check if models were created
if [ -f "models/phishing_detector.tflite" ]; then
    echo "✅ TensorFlow Lite model created successfully"
    ls -la models/phishing_detector.tflite
else
    echo "❌ TensorFlow Lite model not found"
fi

if [ -f "models/lightgbm_phishing_detector.txt" ]; then
    echo "✅ LightGBM model created successfully"
    ls -la models/lightgbm_phishing_detector.txt
else
    echo "❌ LightGBM model not found"
fi

# Copy models to Android assets
ANDROID_ASSETS_DIR="../app/src/main/assets/models"
if [ -d "$ANDROID_ASSETS_DIR" ]; then
    echo "Copying models to Android assets..."
    mkdir -p "$ANDROID_ASSETS_DIR"
    
    if [ -f "models/phishing_detector.tflite" ]; then
        cp models/phishing_detector.tflite "$ANDROID_ASSETS_DIR/"
        echo "✅ TensorFlow Lite model copied to Android assets"
    fi
    
    if [ -f "models/lightgbm_mobile.txt" ]; then
        cp models/lightgbm_mobile.txt "$ANDROID_ASSETS_DIR/"
        echo "✅ LightGBM model copied to Android assets"
    fi
else
    echo "Android assets directory not found. Skipping model copy."
fi

echo "=========================================="
echo "ML Training Complete!"
echo "=========================================="

# Show training results if available
if [ -f "results/training_report.json" ]; then
    echo "Training Results:"
    python3 -c "
import json
with open('results/training_report.json', 'r') as f:
    report = json.load(f)
    
print('Training Date:', report['training_date'])
print('\\nModel Performance:')
for model, metrics in report['model_performance'].items():
    print(f'  {model}:')
    print(f'    AUC Score: {metrics[\"auc_score\"]:.4f}')
    if 'classification_report' in metrics:
        cr = metrics['classification_report']
        if '1' in cr:
            print(f'    Precision: {cr[\"1\"][\"precision\"]:.4f}')
            print(f'    Recall: {cr[\"1\"][\"recall\"]:.4f}')
            print(f'    F1-Score: {cr[\"1\"][\"f1-score\"]:.4f}')

print('\\nRecommendations:')
for rec in report['recommendations']:
    print(f'  - {rec}')
"
fi
