"""
Feature Extractor for PhishShield AI
Extracts comprehensive features from URLs for ML training
"""

import pandas as pd
import numpy as np
import re
import logging
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
import tldextract
import socket
from datetime import datetime
import math

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extracts features from URLs for phishing detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.icu', '.top', '.click']
        self.url_shorteners = ['bit.ly', 'tinyurl.com', 'ow.ly', 't.co', 'goo.gl']
        self.suspicious_keywords = [
            'secure', 'verify', 'update', 'suspend', 'limited', 'expired',
            'confirm', 'validate', 'urgent', 'immediate', 'action', 'required',
            'click', 'here', 'now', 'login', 'signin', 'account'
        ]
    
    def extract_features(self, dataset: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features from URL dataset"""
        logger.info("Extracting features from URLs...")
        
        features_list = []
        labels = dataset['label'].values
        
        for idx, row in dataset.iterrows():
            if idx % 1000 == 0:
                logger.info(f"Processed {idx}/{len(dataset)} URLs")
            
            url = row['url']
            url_features = self._extract_url_features(url)
            features_list.append(url_features)
        
        # Convert to numpy array
        features = np.array(features_list)
        
        logger.info(f"Feature extraction complete. Shape: {features.shape}")
        return features, labels
    
    def _extract_url_features(self, url: str) -> List[float]:
        """Extract all features from a single URL"""
        features = []
        
        try:
            # Parse URL
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Basic URL features
            features.extend(self._extract_basic_features(url, parsed, extracted))
            
            # Lexical features
            features.extend(self._extract_lexical_features(url, parsed, extracted))
            
            # Domain features
            features.extend(self._extract_domain_features(parsed, extracted))
            
            # Path and query features
            features.extend(self._extract_path_query_features(parsed))
            
            # Security features
            features.extend(self._extract_security_features(url, parsed))
            
            # Suspicious pattern features
            features.extend(self._extract_suspicious_pattern_features(url))
            
        except Exception as e:
            logger.warning(f"Error extracting features from {url}: {e}")
            # Return zero-filled feature vector
            features = [0.0] * self._get_feature_count()
        
        return features
    
    def _extract_basic_features(self, url: str, parsed, extracted) -> List[float]:
        """Extract basic URL features"""
        features = []
        
        # URL length
        features.append(len(url))
        
        # Domain length
        features.append(len(parsed.netloc))
        
        # Path length
        features.append(len(parsed.path))
        
        # Query length
        features.append(len(parsed.query) if parsed.query else 0)
        
        # Number of subdomains
        features.append(parsed.netloc.count('.'))
        
        # Has HTTPS
        features.append(1.0 if parsed.scheme == 'https' else 0.0)
        
        # Has port
        features.append(1.0 if parsed.port else 0.0)
        
        # Has fragment
        features.append(1.0 if parsed.fragment else 0.0)
        
        return features
    
    def _extract_lexical_features(self, url: str, parsed, extracted) -> List[float]:
        """Extract lexical analysis features"""
        features = []
        
        # Character distribution
        features.append(url.count('-'))  # Hyphens
        features.append(url.count('_'))  # Underscores
        features.append(url.count('.'))  # Dots
        features.append(url.count('/'))  # Slashes
        features.append(url.count('?'))  # Question marks
        features.append(url.count('='))  # Equals signs
        features.append(url.count('&'))  # Ampersands
        
        # Digit ratio
        digit_count = sum(c.isdigit() for c in url)
        features.append(digit_count / len(url) if len(url) > 0 else 0)
        
        # Alphabetic ratio
        alpha_count = sum(c.isalpha() for c in url)
        features.append(alpha_count / len(url) if len(url) > 0 else 0)
        
        # Entropy calculation
        features.append(self._calculate_entropy(url))
        
        # Longest word length
        words = re.findall(r'[a-zA-Z]+', url)
        features.append(max(len(word) for word in words) if words else 0)
        
        # Average word length
        features.append(sum(len(word) for word in words) / len(words) if words else 0)
        
        return features
    
    def _extract_domain_features(self, parsed, extracted) -> List[float]:
        """Extract domain-specific features"""
        features = []
        
        domain = parsed.netloc.lower()
        
        # Is IP address
        features.append(1.0 if self._is_ip_address(domain) else 0.0)
        
        # Suspicious TLD
        tld = f".{extracted.suffix}"
        features.append(1.0 if tld in self.suspicious_tlds else 0.0)
        
        # URL shortener
        features.append(1.0 if any(shortener in domain for shortener in self.url_shorteners) else 0.0)
        
        # Domain has numbers
        features.append(1.0 if any(c.isdigit() for c in extracted.domain) else 0.0)
        
        # Domain entropy
        features.append(self._calculate_entropy(extracted.domain))
        
        # Subdomain count
        features.append(len(extracted.subdomain.split('.')) if extracted.subdomain else 0)
        
        # Domain length
        features.append(len(extracted.domain))
        
        # TLD length
        features.append(len(extracted.suffix))
        
        return features
    
    def _extract_path_query_features(self, parsed) -> List[float]:
        """Extract path and query parameter features"""
        features = []
        
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Path depth
        features.append(path.count('/'))
        
        # Has file extension
        features.append(1.0 if '.' in path.split('/')[-1] else 0.0)
        
        # Suspicious path keywords
        path_suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in path)
        features.append(path_suspicious_count)
        
        # Query parameter count
        query_params = query.split('&') if query else []
        features.append(len(query_params))
        
        # Query has suspicious keywords
        query_suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in query)
        features.append(query_suspicious_count)
        
        # Query has encoded characters
        features.append(1.0 if '%' in query else 0.0)
        
        return features
    
    def _extract_security_features(self, url: str, parsed) -> List[float]:
        """Extract security-related features"""
        features = []
        
        # Protocol features
        features.append(1.0 if parsed.scheme == 'https' else 0.0)
        features.append(1.0 if parsed.scheme == 'http' else 0.0)
        
        # Non-standard port
        standard_ports = [80, 443]
        features.append(1.0 if parsed.port and parsed.port not in standard_ports else 0.0)
        
        # Has authentication info
        features.append(1.0 if '@' in parsed.netloc else 0.0)
        
        return features
    
    def _extract_suspicious_pattern_features(self, url: str) -> List[float]:
        """Extract suspicious pattern features"""
        features = []
        
        url_lower = url.lower()
        
        # Brand impersonation patterns
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram']
        brand_mentions = sum(1 for brand in brands if brand in url_lower)
        features.append(brand_mentions)
        
        # Suspicious keyword count
        suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
        features.append(suspicious_count)
        
        # Homograph detection (simplified)
        features.append(1.0 if self._has_homograph_chars(url) else 0.0)
        
        # Multiple redirects indicator (URL contains redirect params)
        redirect_params = ['redirect', 'goto', 'url', 'link', 'target', 'continue']
        redirect_indicators = sum(1 for param in redirect_params if param in url_lower)
        features.append(redirect_indicators)
        
        # URL has multiple domains (complex path structure)
        domain_pattern_count = url_lower.count('://') - 1  # Subtract 1 for the main protocol
        features.append(domain_pattern_count)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Get frequency of each character
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False
    
    def _has_homograph_chars(self, url: str) -> bool:
        """Simple homograph character detection"""
        # Check for mix of Latin and other scripts
        latin_chars = sum(1 for c in url if ord(c) < 128)
        non_latin_chars = len(url) - latin_chars
        
        # If more than 10% non-Latin characters, consider suspicious
        return non_latin_chars > 0 and (non_latin_chars / len(url)) > 0.1
    
    def _get_feature_count(self) -> int:
        """Get total number of features"""
        # Calculate based on feature extraction methods
        basic_features = 8
        lexical_features = 12
        domain_features = 8
        path_query_features = 6
        security_features = 4
        suspicious_pattern_features = 5
        
        return basic_features + lexical_features + domain_features + path_query_features + security_features + suspicious_pattern_features
    
    def get_feature_names(self) -> List[str]:
        """Get names of all features"""
        feature_names = []
        
        # Basic features
        feature_names.extend([
            'url_length', 'domain_length', 'path_length', 'query_length',
            'subdomain_count', 'has_https', 'has_port', 'has_fragment'
        ])
        
        # Lexical features
        feature_names.extend([
            'hyphen_count', 'underscore_count', 'dot_count', 'slash_count',
            'question_count', 'equals_count', 'ampersand_count', 'digit_ratio',
            'alpha_ratio', 'url_entropy', 'max_word_length', 'avg_word_length'
        ])
        
        # Domain features
        feature_names.extend([
            'is_ip_address', 'suspicious_tld', 'is_url_shortener', 'domain_has_numbers',
            'domain_entropy', 'subdomain_depth', 'domain_name_length', 'tld_length'
        ])
        
        # Path and query features
        feature_names.extend([
            'path_depth', 'has_file_extension', 'path_suspicious_keywords',
            'query_param_count', 'query_suspicious_keywords', 'query_has_encoding'
        ])
        
        # Security features
        feature_names.extend([
            'is_https', 'is_http', 'non_standard_port', 'has_auth_info'
        ])
        
        # Suspicious pattern features
        feature_names.extend([
            'brand_mentions', 'suspicious_keyword_count', 'has_homograph_chars',
            'redirect_indicators', 'multiple_domain_patterns'
        ])
        
        return feature_names
