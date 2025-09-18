# PhishShield AI - Threat Intelligence Integration

## Overview

PhishShield AI now integrates with multiple threat intelligence sources to provide real-time phishing detection. This document explains the threat intelligence system and how to configure it.

## Architecture

### Threat Intelligence Sources

1. **VirusTotal** - URL/domain reputation from 70+ antivirus engines
2. **Google Safe Browsing** - Google's malicious URL database
3. **PhishTank** - Community-driven phishing URL database
4. **OpenPhish** - Open source phishing feed
5. **URLVoid** - Domain reputation checker
6. **Malware Domain List** - Known malicious domains
7. **IP Reputation** - IP address analysis and reputation

### Integration Points

#### Android App (Layer 3 Enhancement)
- **ThreatIntelligenceService.kt** - Main threat intelligence client
- **Enhanced ML Model** - 48 features (43 original + 5 threat intel)
- **Quick Domain Check** - Fast reputation lookup for DNS interception
- **Cache Management** - 1-hour local cache for performance

#### Backend Services (Layer 0)
- **ThreatIntelligenceService.py** - Comprehensive threat analysis
- **API Endpoints** - RESTful threat intelligence APIs
- **Redis Caching** - Distributed cache for threat data
- **Background Updates** - Automatic threat feed updates

## Setup Instructions

### 1. API Key Configuration

Edit `backend/.env` and add your API keys:

```bash
# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLVOID_API_KEY=your_urlvoid_api_key  
PHISHTANK_API_KEY=your_phishtank_api_key
GOOGLE_SAFEBROWSING_API_KEY=your_google_safebrowsing_api_key

# Threat Feed Settings
THREAT_CACHE_TTL=3600
THREAT_UPDATE_INTERVAL=1800
ENABLE_REALTIME_FEEDS=true
```

### 2. Getting API Keys

#### VirusTotal (Recommended)
- Sign up at: https://www.virustotal.com/gui/join-us
- Free tier: 4 requests/minute
- Provides comprehensive malware/phishing detection

#### Google Safe Browsing (Recommended)  
- Get API key: https://developers.google.com/safe-browsing
- Free tier: 10,000 requests/day
- High-quality phishing detection

#### URLVoid (Optional)
- Sign up at: https://www.urlvoid.com/api/
- Paid service with domain reputation data

#### PhishTank (Optional)
- Register at: https://www.phishtank.com/api_info.php
- Free API with community phishing reports

### 3. Quick Setup

Run the automated setup script:

```powershell
.\setup_threat_intelligence.ps1
```

This script will:
- Configure environment variables
- Install Python dependencies
- Train enhanced ML models
- Start backend services
- Test threat intelligence endpoints

## API Endpoints

### Threat Analysis
```
POST /api/threat-intel/analyze/{url}
```
Comprehensive threat analysis using all sources.

### Domain Intelligence
```
GET /api/threat-intel/domain/{domain}
```
Get threat intelligence for a specific domain.

### Quick Reputation Check
```
GET /api/threat-intel/reputation/{domain}
```
Fast domain reputation lookup.

### Feed Status
```
GET /api/threat-intel/feeds/status
```
Check status of all threat intelligence feeds.

### Report Threat
```
POST /api/threat-intel/report
```
Report a new threat to the system.

## Enhanced Detection Flow

### 1. DNS Interception (VPN Service)
```
Domain Request → Quick Threat Intel Check → Block if Malicious
```

### 2. URL Access (Accessibility Service)
```
URL Detected → Full 7-Layer Analysis → Enhanced ML Prediction
```

### 3. Threat Intelligence Integration
```
Layer 0: Threat Intelligence Pre-check
Layer 1: URL Normalization  
Layer 2: Lexical Analysis
Layer 3: Enhanced Reputation (Local + Cloud)
Layer 4: Content Analysis
Layer 5: Enhanced ML (48 features)
Layer 6: Sandbox Analysis
Layer 7: Network Graph Analysis
```

## Performance Optimizations

### Caching Strategy
- **Local Android Cache**: 1 hour TTL for domain reputation
- **Redis Backend Cache**: 1 hour TTL for full threat analysis
- **Background Updates**: Automatic feed refresh every 30 minutes

### Fallback Mechanisms
- **API Unavailable**: Use cached data and heuristic analysis
- **Rate Limiting**: Implement exponential backoff
- **Network Issues**: Fall back to local ML models

### Threat Score Calculation

The system combines multiple threat sources with weighted scoring:

```
Final Score = (
    ThreatIntel * 0.35 +
    Sandbox * 0.25 + 
    Network * 0.20 +
    ML * 0.20
)
```

## Enhanced ML Features

The ML model now uses 48 features instead of 43:

### Original Features (1-43)
- URL structure analysis
- Domain characteristics  
- Content patterns
- Behavioral indicators

### New Threat Intelligence Features (44-48)
- **Feature 44**: Threat intelligence confidence score
- **Feature 45**: Binary threat intelligence verdict
- **Feature 46**: Aggregated reputation score
- **Feature 47**: Number of threat sources flagging URL
- **Feature 48**: Threat level numeric encoding

## Monitoring and Maintenance

### Feed Status Monitoring
Check threat feed health:
```bash
curl http://localhost:8000/api/threat-intel/feeds/status
```

### Manual Feed Updates
Trigger feed refresh:
```bash
curl -X POST http://localhost:8000/api/threat-intel/feeds/update
```

### Cache Management
Monitor Redis cache usage and hit rates for optimization.

## Security Considerations

### API Key Protection
- Store API keys as environment variables
- Use different keys for development/production
- Monitor API usage and quotas

### Rate Limiting
- Implement client-side rate limiting
- Use exponential backoff for retries
- Cache results to minimize API calls

### Data Privacy
- Hash URLs before external API calls (where possible)
- Implement data retention policies
- Follow GDPR/privacy regulations

## Troubleshooting

### Common Issues

1. **API Keys Not Working**
   - Verify keys in `.env` file
   - Check API quota limits
   - Test with curl commands

2. **High Latency**
   - Check network connectivity
   - Monitor API response times
   - Increase cache TTL

3. **False Positives**
   - Adjust threat score thresholds
   - Whitelist known good domains
   - Fine-tune ML model weights

### Debug Mode
Enable debug logging:
```bash
LOG_LEVEL=DEBUG
```

## Performance Metrics

Expected performance with threat intelligence:
- **Quick Domain Check**: < 100ms (cached)
- **Full URL Analysis**: < 2 seconds
- **Cache Hit Rate**: > 80%
- **False Positive Rate**: < 1%
- **Detection Rate**: > 95%

## Future Enhancements

### Planned Features
- Custom threat feeds integration
- Machine learning model retraining with threat intel data
- Real-time threat intelligence streaming
- Advanced graph analysis with threat attribution
- Threat hunting capabilities

### API Expansion
- Bulk URL analysis endpoints
- Historical threat data queries
- Threat intelligence exports
- Custom rule engine
