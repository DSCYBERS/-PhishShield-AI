"""
Network Analysis Service - Layer 7 Graph-based Analysis
"""

import logging
import socket
import asyncio
import ipaddress
from typing import Dict, Any, List
from urllib.parse import urlparse
import whois
import dns.resolver

logger = logging.getLogger(__name__)

class NetworkAnalysisService:
    """
    Network Graph Analysis Service for detecting phishing campaigns
    """
    
    def __init__(self):
        self.graph_db = None  # Neo4j connection placeholder
        self.suspicious_asns = set()
        self.malicious_ips = set()
        self.trusted_ips = set()
        
        # Initialize with known suspicious patterns
        self._initialize_threat_data()
        
    def _initialize_threat_data(self):
        """Initialize with known threat patterns"""
        # Common suspicious ASNs (example data)
        self.suspicious_asns = {
            "AS12345",  # Example suspicious ASN
            "AS99999"   # Another example
        }
        
        # Known malicious IP ranges (example data)
        self.malicious_ips = {
            "192.168.1.1",  # Example (normally this would be external IPs)
            "10.0.0.1"       # Example
        }
        
        # Trusted infrastructure
        self.trusted_ips = {
            "8.8.8.8",       # Google DNS
            "1.1.1.1",       # Cloudflare DNS
            "208.67.222.222" # OpenDNS
        }
        
    async def analyze_url_network(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL within network context to detect campaigns
        """
        try:
            logger.info(f"Starting network analysis for {url}")
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            result = {
                "campaign_detected": False,
                "cluster_risk_score": 0.0,
                "related_urls": [],
                "ip_reputation": await self._analyze_ip_reputation(domain),
                "domain_cluster": await self._analyze_domain_cluster(domain),
                "dns_analysis": await self._analyze_dns_records(domain),
                "whois_analysis": await self._analyze_whois_data(domain),
                "infrastructure_analysis": await self._analyze_infrastructure(domain)
            }
            
            # Calculate overall cluster risk score
            result["cluster_risk_score"] = self._calculate_cluster_risk(result)
            
            # Determine if this appears to be part of a campaign
            result["campaign_detected"] = result["cluster_risk_score"] > 0.7
            
            logger.info(f"Network analysis complete for {url}: risk_score={result['cluster_risk_score']:.3f}")
            return result
            
        except Exception as e:
            logger.error(f"Network analysis failed for {url}: {e}")
            return {
                "campaign_detected": False,
                "cluster_risk_score": 0.0,
                "related_urls": [],
                "ip_reputation": {"malicious": False, "score": 0.0, "details": "Analysis failed"},
                "domain_cluster": {"cluster_id": None, "cluster_size": 0, "cluster_risk": 0.0},
                "dns_analysis": {"risk_score": 0.0, "suspicious_records": []},
                "whois_analysis": {"risk_score": 0.0, "suspicious_indicators": []},
                "infrastructure_analysis": {"risk_score": 0.0, "hosting_reputation": "unknown"}
            }
    
    async def _analyze_ip_reputation(self, domain: str) -> Dict[str, Any]:
        """Analyze IP reputation for the domain"""
        try:
            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain)
            
            result = {
                "ip_address": ip_address,
                "malicious": False,
                "score": 0.0,
                "details": [],
                "geolocation": "unknown",
                "asn": "unknown"
            }
            
            # Check against known malicious IPs
            if ip_address in self.malicious_ips:
                result["malicious"] = True
                result["score"] = 0.9
                result["details"].append("IP found in malicious database")
            
            # Check against trusted IPs
            elif ip_address in self.trusted_ips:
                result["score"] = 0.1
                result["details"].append("IP found in trusted database")
            
            # Check for suspicious IP patterns
            else:
                risk_score = await self._assess_ip_risk(ip_address)
                result["score"] = risk_score
                result["malicious"] = risk_score > 0.7
            
            return result
            
        except Exception as e:
            logger.warning(f"IP reputation analysis failed for {domain}: {e}")
            return {
                "ip_address": "unknown",
                "malicious": False,
                "score": 0.5,
                "details": [f"Resolution failed: {str(e)}"],
                "geolocation": "unknown",
                "asn": "unknown"
            }
    
    async def _assess_ip_risk(self, ip_address: str) -> float:
        """Assess risk score for an IP address"""
        try:
            risk_score = 0.0
            
            # Parse IP address
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Check if it's a private IP (suspicious for public websites)
            if ip_obj.is_private:
                risk_score += 0.3
            
            # Check if it's in suspicious ranges
            if ip_obj.is_reserved or ip_obj.is_loopback:
                risk_score += 0.5
            
            # Simple heuristics for suspicious patterns
            octets = ip_address.split('.')
            if len(octets) == 4:
                # Check for patterns like x.x.x.1 (often suspicious)
                if octets[3] == '1':
                    risk_score += 0.1
                
                # Check for sequential patterns
                try:
                    nums = [int(o) for o in octets]
                    if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                        risk_score += 0.1
                except ValueError:
                    pass
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.warning(f"IP risk assessment failed for {ip_address}: {e}")
            return 0.5
    
    async def _analyze_domain_cluster(self, domain: str) -> Dict[str, Any]:
        """Analyze domain within cluster context"""
        try:
            result = {
                "cluster_id": None,
                "cluster_size": 0,
                "cluster_risk": 0.0,
                "similar_domains": [],
                "domain_variations": []
            }
            
            # Generate potential domain variations
            variations = self._generate_domain_variations(domain)
            result["domain_variations"] = variations[:10]  # Limit to 10
            
            # Simple clustering based on domain patterns
            cluster_risk = 0.0
            
            # Check for suspicious domain patterns
            if any(keyword in domain.lower() for keyword in ['secure', 'verify', 'account', 'login']):
                cluster_risk += 0.3
            
            # Check for typosquatting patterns
            if self._check_typosquatting_patterns(domain):
                cluster_risk += 0.4
            
            result["cluster_risk"] = min(cluster_risk, 1.0)
            result["cluster_size"] = len(variations)
            
            return result
            
        except Exception as e:
            logger.warning(f"Domain cluster analysis failed for {domain}: {e}")
            return {
                "cluster_id": None,
                "cluster_size": 0,
                "cluster_risk": 0.0,
                "similar_domains": [],
                "domain_variations": []
            }
    
    def _generate_domain_variations(self, domain: str) -> List[str]:
        """Generate potential typosquatting variations"""
        variations = []
        base_domain = domain.lower()
        
        # Character substitution variations
        substitutions = {
            'o': '0', '0': 'o', 'l': '1', '1': 'l',
            'e': '3', '3': 'e', 'a': '@', 's': '$'
        }
        
        for char, replacement in substitutions.items():
            if char in base_domain:
                variation = base_domain.replace(char, replacement, 1)
                variations.append(variation)
        
        # Character insertion variations
        common_insertions = ['-', '_', '1', '2']
        for insertion in common_insertions:
            # Insert at different positions
            for i in range(1, min(len(base_domain), 5)):
                variation = base_domain[:i] + insertion + base_domain[i:]
                variations.append(variation)
        
        return list(set(variations))
    
    def _check_typosquatting_patterns(self, domain: str) -> bool:
        """Check for common typosquatting patterns"""
        patterns = [
            r'\w+\-\w+\-\w+',  # Multiple hyphens
            r'\w+\d+\w+',       # Numbers in the middle
            r'\w{20,}',         # Very long domains
        ]
        
        import re
        for pattern in patterns:
            if re.search(pattern, domain):
                return True
        
        return False
    
    async def _analyze_dns_records(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records for suspicious patterns"""
        try:
            result = {
                "risk_score": 0.0,
                "suspicious_records": [],
                "mx_records": [],
                "txt_records": [],
                "ns_records": []
            }
            
            # Try to get various DNS records
            try:
                # MX records
                mx_records = dns.resolver.resolve(domain, 'MX')
                result["mx_records"] = [str(mx) for mx in mx_records]
                
                # Check for suspicious MX patterns
                for mx in result["mx_records"]:
                    if 'suspicious' in mx.lower() or 'temp' in mx.lower():
                        result["risk_score"] += 0.2
                        result["suspicious_records"].append(f"Suspicious MX: {mx}")
                        
            except Exception:
                result["suspicious_records"].append("No MX records found")
                result["risk_score"] += 0.1
            
            try:
                # NS records
                ns_records = dns.resolver.resolve(domain, 'NS')
                result["ns_records"] = [str(ns) for ns in ns_records]
                
            except Exception:
                result["suspicious_records"].append("No NS records found")
                result["risk_score"] += 0.1
            
            return result
            
        except Exception as e:
            logger.warning(f"DNS analysis failed for {domain}: {e}")
            return {
                "risk_score": 0.5,
                "suspicious_records": [f"DNS analysis failed: {str(e)}"],
                "mx_records": [],
                "txt_records": [],
                "ns_records": []
            }
    
    async def _analyze_whois_data(self, domain: str) -> Dict[str, Any]:
        """Analyze WHOIS data for suspicious indicators"""
        try:
            result = {
                "risk_score": 0.0,
                "suspicious_indicators": [],
                "creation_date": None,
                "registrar": None,
                "registrant_country": None
            }
            
            # Get WHOIS data
            w = whois.whois(domain)
            
            if w:
                # Check domain age
                if w.creation_date:
                    creation_date = w.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    result["creation_date"] = str(creation_date)
                    
                    # Very new domains are suspicious
                    from datetime import datetime, timedelta
                    if datetime.now() - creation_date < timedelta(days=30):
                        result["risk_score"] += 0.4
                        result["suspicious_indicators"].append("Very new domain (< 30 days)")
                    elif datetime.now() - creation_date < timedelta(days=90):
                        result["risk_score"] += 0.2
                        result["suspicious_indicators"].append("New domain (< 90 days)")
                
                # Check registrar
                if w.registrar:
                    result["registrar"] = w.registrar
                    # Some registrars are commonly used for malicious domains
                    suspicious_registrars = ['namecheap', 'freenom']
                    if any(susp in w.registrar.lower() for susp in suspicious_registrars):
                        result["risk_score"] += 0.1
                        result["suspicious_indicators"].append("Suspicious registrar")
                
                # Check registrant country
                if hasattr(w, 'country') and w.country:
                    result["registrant_country"] = w.country
            
            return result
            
        except Exception as e:
            logger.warning(f"WHOIS analysis failed for {domain}: {e}")
            return {
                "risk_score": 0.3,
                "suspicious_indicators": [f"WHOIS lookup failed: {str(e)}"],
                "creation_date": None,
                "registrar": None,
                "registrant_country": None
            }
    
    async def _analyze_infrastructure(self, domain: str) -> Dict[str, Any]:
        """Analyze hosting infrastructure"""
        try:
            result = {
                "risk_score": 0.0,
                "hosting_reputation": "unknown",
                "hosting_provider": "unknown",
                "infrastructure_flags": []
            }
            
            # Basic infrastructure analysis
            # In a real implementation, this would check against threat feeds
            
            # Check for common suspicious hosting patterns
            if any(keyword in domain.lower() for keyword in ['hosting', 'server', 'vps']):
                result["risk_score"] += 0.1
                result["infrastructure_flags"].append("Generic hosting domain pattern")
            
            # Placeholder for more sophisticated infrastructure analysis
            result["hosting_reputation"] = "neutral"
            
            return result
            
        except Exception as e:
            logger.warning(f"Infrastructure analysis failed for {domain}: {e}")
            return {
                "risk_score": 0.3,
                "hosting_reputation": "unknown",
                "hosting_provider": "unknown",
                "infrastructure_flags": [f"Analysis failed: {str(e)}"]
            }
    
    def _calculate_cluster_risk(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate overall cluster risk score"""
        try:
            weights = {
                "ip_reputation": 0.3,
                "domain_cluster": 0.25,
                "dns_analysis": 0.2,
                "whois_analysis": 0.15,
                "infrastructure_analysis": 0.1
            }
            
            total_score = 0.0
            total_weight = 0.0
            
            for component, weight in weights.items():
                if component in analysis_result:
                    component_score = analysis_result[component].get("risk_score", 0.0)
                    if component == "ip_reputation":
                        component_score = analysis_result[component].get("score", 0.0)
                    elif component == "domain_cluster":
                        component_score = analysis_result[component].get("cluster_risk", 0.0)
                    
                    total_score += component_score * weight
                    total_weight += weight
            
            return total_score / total_weight if total_weight > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Cluster risk calculation failed: {e}")
            return 0.5
            }
