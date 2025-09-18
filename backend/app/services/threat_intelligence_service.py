"""
Threat Intelligence Service - Real-time threat data integration
Connects to multiple threat feeds for enhanced phishing detection
"""

import logging
import asyncio
import aiohttp
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import os
import redis
from urllib.parse import urlparse, quote

logger = logging.getLogger(__name__)

class ThreatIntelligenceService:
    """
    Centralized threat intelligence service connecting multiple data sources
    """
    
    def __init__(self):
        self.redis_client = None
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'urlvoid': os.getenv('URLVOID_API_KEY'),
            'safebrowsing': os.getenv('GOOGLE_SAFEBROWSING_API_KEY'),
            'phishtank': os.getenv('PHISHTANK_API_KEY'),
            'openphish': None,  # Open source
            'malwaredomainlist': None,  # Open source
        }
        self.cache_ttl = 3600  # 1 hour cache
        
    async def initialize(self):
        """Initialize connections and cache"""
        try:
            self.redis_client = redis.asyncio.Redis(
                host=os.getenv('REDIS_HOST', 'localhost'),
                port=int(os.getenv('REDIS_PORT', 6379)),
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Threat intelligence service initialized")
        except Exception as e:
            logger.error(f"Failed to initialize threat intelligence: {e}")
    
    async def analyze_url_threats(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive threat analysis using multiple sources
        """
        url_hash = hashlib.md5(url.encode()).hexdigest()
        cache_key = f"threat_analysis:{url_hash}"
        
        # Check cache first
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        # Parallel threat source checks
        tasks = [
            self._check_virustotal(url),
            self._check_safebrowsing(url),
            self._check_phishtank(url),
            self._check_openphish(url),
            self._check_urlvoid(url),
            self._check_malware_domain_list(url),
            self._check_ip_reputation(url)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        threat_score = 0.0
        threat_sources = []
        detailed_results = {}
        
        source_names = ['virustotal', 'safebrowsing', 'phishtank', 'openphish', 
                       'urlvoid', 'malware_domains', 'ip_reputation']
        
        for i, result in enumerate(results):
            if not isinstance(result, Exception) and result:
                source_name = source_names[i]
                detailed_results[source_name] = result
                
                if result.get('is_malicious'):
                    threat_score += result.get('confidence', 0.5)
                    threat_sources.append({
                        'source': source_name,
                        'confidence': result.get('confidence', 0.5),
                        'category': result.get('category', 'unknown')
                    })
        
        # Normalize threat score (0-1)
        threat_score = min(threat_score / len(source_names), 1.0)
        
        final_result = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'threat_score': threat_score,
            'is_malicious': threat_score > 0.3,
            'threat_sources': threat_sources,
            'detailed_results': detailed_results,
            'reputation': self._calculate_reputation(threat_score),
            'categories': self._extract_categories(detailed_results)
        }
        
        # Cache result
        await self._cache_result(cache_key, final_result)
        
        return final_result
    
    async def _check_virustotal(self, url: str) -> Optional[Dict[str, Any]]:
        """Check VirusTotal for URL reputation"""
        if not self.api_keys['virustotal']:
            return None
            
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'https://www.virustotal.com/api/v3/urls/{url_id}',
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        if total > 0:
                            confidence = (malicious + suspicious * 0.5) / total
                            return {
                                'is_malicious': malicious > 0,
                                'confidence': confidence,
                                'category': 'phishing' if malicious > 0 else 'clean',
                                'detections': malicious,
                                'total_scans': total
                            }
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
        
        return None
    
    async def _check_safebrowsing(self, url: str) -> Optional[Dict[str, Any]]:
        """Check Google Safe Browsing API"""
        if not self.api_keys['safebrowsing']:
            return None
            
        try:
            payload = {
                'client': {
                    'clientId': 'PhishShield',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_keys["safebrowsing"]}',
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        matches = data.get('matches', [])
                        
                        if matches:
                            threat_type = matches[0].get('threatType', 'UNKNOWN')
                            return {
                                'is_malicious': True,
                                'confidence': 0.9,
                                'category': 'phishing' if threat_type == 'SOCIAL_ENGINEERING' else 'malware',
                                'threat_type': threat_type
                            }
                        else:
                            return {
                                'is_malicious': False,
                                'confidence': 0.1,
                                'category': 'clean'
                            }
        except Exception as e:
            logger.error(f"Safe Browsing check failed: {e}")
        
        return None
    
    async def _check_phishtank(self, url: str) -> Optional[Dict[str, Any]]:
        """Check PhishTank database"""
        try:
            payload = {
                'url': quote(url, safe=''),
                'format': 'json'
            }
            
            if self.api_keys['phishtank']:
                payload['app_key'] = self.api_keys['phishtank']
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'http://checkurl.phishtank.com/checkurl/',
                    data=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('results', {}).get('in_database'):
                            return {
                                'is_malicious': True,
                                'confidence': 0.95,
                                'category': 'phishing',
                                'verified': data.get('results', {}).get('verified', False)
                            }
                        else:
                            return {
                                'is_malicious': False,
                                'confidence': 0.1,
                                'category': 'clean'
                            }
        except Exception as e:
            logger.error(f"PhishTank check failed: {e}")
        
        return None
    
    async def _check_openphish(self, url: str) -> Optional[Dict[str, Any]]:
        """Check OpenPhish feed"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://openphish.com/feed.txt') as response:
                    if response.status == 200:
                        feed_data = await response.text()
                        urls = feed_data.strip().split('\n')
                        
                        if url in urls:
                            return {
                                'is_malicious': True,
                                'confidence': 0.9,
                                'category': 'phishing'
                            }
                        else:
                            return {
                                'is_malicious': False,
                                'confidence': 0.1,
                                'category': 'clean'
                            }
        except Exception as e:
            logger.error(f"OpenPhish check failed: {e}")
        
        return None
    
    async def _check_urlvoid(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URLVoid for domain reputation"""
        if not self.api_keys['urlvoid']:
            return None
            
        try:
            domain = urlparse(url).netloc
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'https://api.urlvoid.com/v1/pay-as-you-go/?key={self.api_keys["urlvoid"]}&host={domain}'
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        detections = data.get('data', {}).get('report', {}).get('blacklists', {}).get('detections', 0)
                        engines = data.get('data', {}).get('report', {}).get('blacklists', {}).get('engines_count', 1)
                        
                        confidence = detections / engines if engines > 0 else 0
                        
                        return {
                            'is_malicious': detections > 0,
                            'confidence': confidence,
                            'category': 'malicious' if detections > 0 else 'clean',
                            'detections': detections,
                            'total_engines': engines
                        }
        except Exception as e:
            logger.error(f"URLVoid check failed: {e}")
        
        return None
    
    async def _check_malware_domain_list(self, url: str) -> Optional[Dict[str, Any]]:
        """Check Malware Domain List"""
        try:
            domain = urlparse(url).netloc
            async with aiohttp.ClientSession() as session:
                async with session.get('http://www.malwaredomainlist.com/hostslist/hosts.txt') as response:
                    if response.status == 200:
                        hosts_data = await response.text()
                        
                        if domain in hosts_data:
                            return {
                                'is_malicious': True,
                                'confidence': 0.8,
                                'category': 'malware'
                            }
                        else:
                            return {
                                'is_malicious': False,
                                'confidence': 0.1,
                                'category': 'clean'
                            }
        except Exception as e:
            logger.error(f"Malware Domain List check failed: {e}")
        
        return None
    
    async def _check_ip_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation for the domain"""
        try:
            import socket
            domain = urlparse(url).netloc
            
            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain)
            
            # Check common reputation sources
            reputation_score = 0.0
            
            # Simple heuristics for suspicious IPs
            ip_parts = ip_address.split('.')
            
            # Check for private/local IPs (suspicious for public sites)
            if (ip_parts[0] in ['10', '172', '192'] or 
                ip_address.startswith('127.') or 
                ip_address.startswith('169.254.')):
                reputation_score += 0.3
            
            # Check for dynamic IP ranges (more suspicious)
            if any(keyword in domain.lower() for keyword in ['dynamic', 'dhcp', 'dial', 'dsl', 'cable']):
                reputation_score += 0.4
            
            return {
                'is_malicious': reputation_score > 0.5,
                'confidence': reputation_score,
                'category': 'suspicious' if reputation_score > 0.3 else 'clean',
                'ip_address': ip_address,
                'reputation_score': reputation_score
            }
            
        except Exception as e:
            logger.error(f"IP reputation check failed: {e}")
        
        return None
    
    def _calculate_reputation(self, threat_score: float) -> str:
        """Calculate overall reputation based on threat score"""
        if threat_score >= 0.7:
            return 'malicious'
        elif threat_score >= 0.4:
            return 'suspicious'
        elif threat_score >= 0.2:
            return 'questionable'
        else:
            return 'clean'
    
    def _extract_categories(self, detailed_results: Dict) -> List[str]:
        """Extract threat categories from detailed results"""
        categories = set()
        
        for source_data in detailed_results.values():
            if source_data and source_data.get('category'):
                categories.add(source_data['category'])
        
        return list(categories)
    
    async def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached threat analysis result"""
        try:
            if self.redis_client:
                cached_data = await self.redis_client.get(cache_key)
                if cached_data:
                    return json.loads(cached_data)
        except Exception as e:
            logger.error(f"Cache read failed: {e}")
        
        return None
    
    async def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache threat analysis result"""
        try:
            if self.redis_client:
                await self.redis_client.setex(
                    cache_key, 
                    self.cache_ttl, 
                    json.dumps(result, default=str)
                )
        except Exception as e:
            logger.error(f"Cache write failed: {e}")
    
    async def get_threat_feeds_status(self) -> Dict[str, Any]:
        """Get status of all threat intelligence feeds"""
        status = {}
        
        for source, api_key in self.api_keys.items():
            status[source] = {
                'configured': api_key is not None,
                'available': True,  # TODO: Add actual health checks
                'last_update': datetime.utcnow().isoformat()
            }
        
        return status
    
    async def update_threat_feeds(self):
        """Update local threat feed caches"""
        logger.info("Updating threat intelligence feeds...")
        
        try:
            # Update OpenPhish feed
            async with aiohttp.ClientSession() as session:
                async with session.get('https://openphish.com/feed.txt') as response:
                    if response.status == 200:
                        feed_data = await response.text()
                        if self.redis_client:
                            await self.redis_client.setex(
                                'openphish_feed', 
                                3600, 
                                feed_data
                            )
            
            logger.info("Threat feeds updated successfully")
            
        except Exception as e:
            logger.error(f"Failed to update threat feeds: {e}")

# Global instance
threat_intelligence = ThreatIntelligenceService()
