#!/usr/bin/env python3
"""
PhishShield AI - Simplified Backend Demo
Minimal dependencies version for quick testing
"""

import json
import http.server
import socketserver
import urllib.parse
from datetime import datetime
import webbrowser
import sys
import os

class PhishShieldDemoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/demo.html'
        elif self.path == '/api/health':
            self.send_json_response({
                "status": "healthy",
                "service": "PhishShield AI Demo",
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0"
            })
            return
        elif self.path.startswith('/api/'):
            self.handle_api_request()
            return
        super().do_GET()
    
    def do_POST(self):
        if self.path == '/api/v1/analysis/scan':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                url = data.get('url', '')
                
                # Simple demo analysis
                result = self.analyze_url_demo(url)
                self.send_json_response(result)
            except Exception as e:
                self.send_json_response({"error": str(e)}, 400)
        else:
            self.send_json_response({"error": "Not found"}, 404)
    
    def analyze_url_demo(self, url):
        """Demo URL analysis - simulates real PhishShield results"""
        
        # Simple threat detection logic for demo
        suspicious_patterns = ['phish', 'fake', 'secure-bank', 'paypal-verify', 'amazon-security']
        is_suspicious = any(pattern in url.lower() for pattern in suspicious_patterns)
        
        if is_suspicious:
            return {
                "url": url,
                "is_malicious": True,
                "threat_level": "high",
                "confidence": 0.89,
                "analysis_layers": ["Lexical", "ThreatIntel", "ML", "Content"],
                "scan_time": 0.8,
                "details": {
                    "risk_factors": ["Suspicious domain pattern", "Known phishing keywords"],
                    "ml_prediction": 0.91,
                    "threat_categories": ["phishing", "credential_theft"]
                }
            }
        else:
            return {
                "url": url,
                "is_malicious": False,
                "threat_level": "low",
                "confidence": 0.95,
                "analysis_layers": ["Lexical", "ThreatIntel", "ML", "Content"],
                "scan_time": 0.3,
                "details": {
                    "risk_factors": [],
                    "ml_prediction": 0.05,
                    "threat_categories": []
                }
            }
    
    def handle_api_request(self):
        """Handle API requests with demo data"""
        if self.path == '/api/stats':
            self.send_json_response({
                "total_scans": 15420,
                "threats_blocked": 1205,
                "accuracy": 97.8,
                "avg_response_time": 0.09,
                "active_users": 2340
            })
        elif self.path == '/api/features':
            self.send_json_response({
                "ml_features": 48,
                "analysis_layers": 7,
                "threat_sources": ["VirusTotal", "PhishTank", "Google SafeBrowsing"],
                "supported_platforms": ["Android", "API"],
                "capabilities": [
                    "Real-time URL scanning",
                    "On-device ML inference",
                    "VPN protection",
                    "Accessibility service integration",
                    "Threat intelligence feeds"
                ]
            })
        else:
            self.send_json_response({"error": "API endpoint not found"}, 404)
    
    def send_json_response(self, data, status=200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        response = json.dumps(data, indent=2)
        self.wfile.write(response.encode())

def create_demo_html():
    """Create demo HTML file"""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishShield AI - Live Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .container { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 15px; padding: 30px; margin: 20px 0; }
        .header { text-align: center; margin-bottom: 30px; }
        .api-test { background: rgba(255,255,255,0.05); padding: 20px; border-radius: 10px; margin: 15px 0; }
        .demo-section { margin: 20px 0; }
        input, button { padding: 10px; margin: 5px; border: none; border-radius: 5px; }
        input { background: rgba(255,255,255,0.9); color: #333; width: 300px; }
        button { background: #4CAF50; color: white; cursor: pointer; }
        button:hover { background: #45a049; }
        .result { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; margin: 10px 0; }
        .threat-high { border-left: 5px solid #ff4444; }
        .threat-low { border-left: 5px solid #44ff44; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-card { background: rgba(255,255,255,0.1); padding: 15px; border-radius: 10px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ PhishShield AI - Live Demo</h1>
        <p>Next-Generation Phishing Protection System</p>
    </div>

    <div class="container">
        <h2>🔍 URL Analysis Test</h2>
        <div class="api-test">
            <input type="text" id="urlInput" placeholder="Enter URL to analyze (try: https://fake-paypal-verify.com)" value="https://secure-bank-login.fake.com">
            <button onclick="analyzeUrl()">Analyze URL</button>
            <div id="analysisResult" class="result"></div>
        </div>
    </div>

    <div class="container">
        <h2>📊 System Statistics</h2>
        <div id="statsContainer" class="stats"></div>
    </div>

    <div class="container">
        <h2>🚀 Features & Capabilities</h2>
        <div id="featuresContainer"></div>
    </div>

    <script>
        // Load stats and features on page load
        loadStats();
        loadFeatures();

        async function analyzeUrl() {
            const url = document.getElementById('urlInput').value;
            const resultDiv = document.getElementById('analysisResult');
            
            if (!url) {
                resultDiv.innerHTML = '<p style="color: #ff4444;">Please enter a URL</p>';
                return;
            }

            resultDiv.innerHTML = '<p>🔄 Analyzing URL...</p>';

            try {
                const response = await fetch('/api/v1/analysis/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                const result = await response.json();
                
                const threatClass = result.is_malicious ? 'threat-high' : 'threat-low';
                const threatIcon = result.is_malicious ? '🚨' : '✅';
                const threatText = result.is_malicious ? 'THREAT DETECTED' : 'SAFE';
                
                resultDiv.className = `result ${threatClass}`;
                resultDiv.innerHTML = `
                    <h3>${threatIcon} ${threatText}</h3>
                    <p><strong>URL:</strong> ${result.url}</p>
                    <p><strong>Threat Level:</strong> ${result.threat_level.toUpperCase()}</p>
                    <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
                    <p><strong>Scan Time:</strong> ${result.scan_time}s</p>
                    <p><strong>Analysis Layers:</strong> ${result.analysis_layers.join(', ')}</p>
                    <p><strong>ML Prediction:</strong> ${(result.details.ml_prediction * 100).toFixed(1)}%</p>
                    ${result.details.risk_factors.length > 0 ? 
                        `<p><strong>Risk Factors:</strong> ${result.details.risk_factors.join(', ')}</p>` : ''}
                `;
            } catch (error) {
                resultDiv.innerHTML = `<p style="color: #ff4444;">Error: ${error.message}</p>`;
            }
        }

        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                
                document.getElementById('statsContainer').innerHTML = `
                    <div class="stat-card">
                        <h3>📈 Total Scans</h3>
                        <p style="font-size: 2em; color: #4CAF50;">${stats.total_scans.toLocaleString()}</p>
                    </div>
                    <div class="stat-card">
                        <h3>🛡️ Threats Blocked</h3>
                        <p style="font-size: 2em; color: #ff6b6b;">${stats.threats_blocked.toLocaleString()}</p>
                    </div>
                    <div class="stat-card">
                        <h3>🎯 Accuracy</h3>
                        <p style="font-size: 2em; color: #4ecdc4;">${stats.accuracy}%</p>
                    </div>
                    <div class="stat-card">
                        <h3>⚡ Avg Response</h3>
                        <p style="font-size: 2em; color: #45b7d1;">${stats.avg_response_time}s</p>
                    </div>
                `;
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        async function loadFeatures() {
            try {
                const response = await fetch('/api/features');
                const features = await response.json();
                
                document.getElementById('featuresContainer').innerHTML = `
                    <div class="demo-section">
                        <h3>🧠 ML Model: ${features.ml_features} Features</h3>
                        <h3>🔄 Analysis Pipeline: ${features.analysis_layers} Layers</h3>
                        <h3>🌐 Threat Sources: ${features.threat_sources.join(', ')}</h3>
                        
                        <h4>🚀 Key Capabilities:</h4>
                        <ul>
                            ${features.capabilities.map(cap => `<li>${cap}</li>`).join('')}
                        </ul>
                        
                        <h4>📱 Supported Platforms:</h4>
                        <p>${features.supported_platforms.join(', ')}</p>
                    </div>
                `;
            } catch (error) {
                console.error('Failed to load features:', error);
            }
        }

        // Test some URLs on load
        const testUrls = [
            'https://fake-paypal-verify.com',
            'https://secure-bank-login.fake.com',
            'https://amazon-security-alert.phish.com',
            'https://google.com',
            'https://github.com'
        ];

        // Add test buttons
        setTimeout(() => {
            const container = document.querySelector('.api-test');
            const testDiv = document.createElement('div');
            testDiv.innerHTML = `
                <h4>🧪 Quick Test URLs:</h4>
                ${testUrls.map(url => 
                    `<button onclick="document.getElementById('urlInput').value='${url}'; analyzeUrl();" style="margin: 2px; font-size: 0.8em;">${url}</button>`
                ).join('')}
            `;
            container.appendChild(testDiv);
        }, 1000);
    </script>
</body>
</html>"""
    
    with open('demo.html', 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    """Main function to start the demo server"""
    print("🛡️ PhishShield AI - Starting Demo Server...")
    print("=" * 50)
    
    # Create demo HTML file
    create_demo_html()
    print("✅ Demo files created")
    
    # Start server
    PORT = 8080
    handler = PhishShieldDemoHandler
    
    try:
        with socketserver.TCPServer(("", PORT), handler) as httpd:
            print(f"🌐 Server running at: http://localhost:{PORT}")
            print(f"📊 Demo page: http://localhost:{PORT}/demo.html")
            print(f"🔍 API health: http://localhost:{PORT}/api/health")
            print("\n🚀 Opening demo in browser...")
            
            # Try to open browser
            try:
                webbrowser.open(f'http://localhost:{PORT}/demo.html')
            except:
                print("⚠️ Could not open browser automatically")
            
            print("\n🛑 Press Ctrl+C to stop the server")
            print("=" * 50)
            
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except OSError as e:
        if "already in use" in str(e):
            print(f"❌ Port {PORT} is already in use!")
            print(f"💡 Try: http://localhost:{PORT}/demo.html")
        else:
            print(f"❌ Error starting server: {e}")

if __name__ == "__main__":
    main()
