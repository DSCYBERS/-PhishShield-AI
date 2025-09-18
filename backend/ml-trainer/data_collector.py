"""
Data Collector for PhishShield AI
Collects and preprocesses phishing and legitimate URLs for training
"""

import requests
import pandas as pd
import numpy as np
import logging
from typing import List, Dict, Any, Tuple
from pathlib import Path
import time
from urllib.parse import urlparse
import random

logger = logging.getLogger(__name__)

class PhishingDataCollector:
    """Collects phishing and legitimate URLs for training"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.data_sources = {
            "phishing": [
                "https://data.phishtank.com/data/online-valid.csv",
                "https://openphish.com/feed.txt",
                "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
            ],
            "legitimate": [
                "https://raw.githubusercontent.com/majestic-million/Million-Domain-List/master/csv/majestic_million.csv",
                "https://tranco-list.eu/top-1m.csv.zip"
            ]
        }
    
    def collect_training_data(self) -> pd.DataFrame:
        """Collect comprehensive training dataset"""
        logger.info("Starting data collection...")
        
        # Collect phishing URLs
        phishing_urls = self._collect_phishing_urls()
        logger.info(f"Collected {len(phishing_urls)} phishing URLs")
        
        # Collect legitimate URLs
        legitimate_urls = self._collect_legitimate_urls()
        logger.info(f"Collected {len(legitimate_urls)} legitimate URLs")
        
        # Create balanced dataset
        dataset = self._create_balanced_dataset(phishing_urls, legitimate_urls)
        logger.info(f"Created balanced dataset with {len(dataset)} samples")
        
        # Add synthetic phishing variants
        dataset = self._add_synthetic_variants(dataset)
        logger.info(f"Added synthetic variants, total: {len(dataset)} samples")
        
        return dataset
    
    def _collect_phishing_urls(self) -> List[str]:
        """Collect phishing URLs from various sources"""
        phishing_urls = []
        
        # PhishTank data
        try:
            phishtank_urls = self._fetch_phishtank_data()
            phishing_urls.extend(phishtank_urls)
        except Exception as e:
            logger.warning(f"Failed to fetch PhishTank data: {e}")
        
        # OpenPhish data
        try:
            openphish_urls = self._fetch_openphish_data()
            phishing_urls.extend(openphish_urls)
        except Exception as e:
            logger.warning(f"Failed to fetch OpenPhish data: {e}")
        
        # Local phishing database (if exists)
        local_phishing = self._load_local_phishing_data()
        phishing_urls.extend(local_phishing)
        
        # Remove duplicates and invalid URLs
        phishing_urls = list(set(phishing_urls))
        phishing_urls = [url for url in phishing_urls if self._is_valid_url(url)]
        
        # Limit to configured amount
        max_phishing = self.config["data"]["phishing_urls"]
        if len(phishing_urls) > max_phishing:
            phishing_urls = random.sample(phishing_urls, max_phishing)
        
        return phishing_urls
    
    def _collect_legitimate_urls(self) -> List[str]:
        """Collect legitimate URLs from various sources"""
        legitimate_urls = []
        
        # Alexa Top Sites (via Majestic Million)
        try:
            majestic_urls = self._fetch_majestic_million()
            legitimate_urls.extend(majestic_urls)
        except Exception as e:
            logger.warning(f"Failed to fetch Majestic Million: {e}")
        
        # Tranco list
        try:
            tranco_urls = self._fetch_tranco_list()
            legitimate_urls.extend(tranco_urls)
        except Exception as e:
            logger.warning(f"Failed to fetch Tranco list: {e}")
        
        # Popular domains (hardcoded)
        popular_domains = self._get_popular_domains()
        legitimate_urls.extend(popular_domains)
        
        # Remove duplicates
        legitimate_urls = list(set(legitimate_urls))
        
        # Limit to configured amount
        max_legitimate = self.config["data"]["legitimate_urls"]
        if len(legitimate_urls) > max_legitimate:
            legitimate_urls = random.sample(legitimate_urls, max_legitimate)
        
        return legitimate_urls
    
    def _fetch_phishtank_data(self) -> List[str]:
        """Fetch data from PhishTank"""
        # Note: This is a simplified version. Real implementation would need API key
        urls = [
            # Example phishing URLs (replace with real data source)
            "http://paypal-security-update.fake-domain.com/login",
            "https://amazon-verify-account.suspicious-site.org/signin",
            "http://google-security-alert.malicious-domain.net/verify",
            "https://microsoft-account-suspended.phishing-site.com/login",
            "http://bank-of-america-verify.fake-bank.org/signin"
        ]
        return urls
    
    def _fetch_openphish_data(self) -> List[str]:
        """Fetch data from OpenPhish"""
        try:
            response = requests.get("https://openphish.com/feed.txt", timeout=30)
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                return [url.strip() for url in urls if url.strip()]
        except Exception as e:
            logger.error(f"Error fetching OpenPhish data: {e}")
        return []
    
    def _load_local_phishing_data(self) -> List[str]:
        """Load local phishing database"""
        local_file = Path("datasets/phishing_urls.txt")
        if local_file.exists():
            with open(local_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return []
    
    def _fetch_majestic_million(self) -> List[str]:
        """Fetch Majestic Million top domains"""
        legitimate_domains = [
            "https://google.com", "https://youtube.com", "https://facebook.com",
            "https://amazon.com", "https://wikipedia.org", "https://yahoo.com",
            "https://reddit.com", "https://netflix.com", "https://instagram.com",
            "https://linkedin.com", "https://twitter.com", "https://microsoft.com",
            "https://apple.com", "https://github.com", "https://stackoverflow.com",
            "https://ebay.com", "https://cnn.com", "https://bbc.com",
            "https://paypal.com", "https://spotify.com"
        ]
        return legitimate_domains
    
    def _fetch_tranco_list(self) -> List[str]:
        """Fetch Tranco top domains"""
        # Simplified - in real implementation, download and parse the CSV
        return []
    
    def _get_popular_domains(self) -> List[str]:
        """Get hardcoded popular legitimate domains"""
        return [
            "https://news.google.com", "https://mail.google.com",
            "https://docs.google.com", "https://drive.google.com",
            "https://maps.google.com", "https://play.google.com",
            "https://support.microsoft.com", "https://office.com",
            "https://outlook.com", "https://onedrive.com",
            "https://www.apple.com", "https://support.apple.com",
            "https://developer.apple.com", "https://www.icloud.com"
        ]
    
    def _create_balanced_dataset(self, phishing_urls: List[str], legitimate_urls: List[str]) -> pd.DataFrame:
        """Create balanced dataset with labels"""
        # Create DataFrame
        phishing_df = pd.DataFrame({
            'url': phishing_urls,
            'label': 1,  # 1 = phishing
            'source': 'phishing_feeds'
        })
        
        legitimate_df = pd.DataFrame({
            'url': legitimate_urls,
            'label': 0,  # 0 = legitimate
            'source': 'legitimate_feeds'
        })
        
        # Combine and shuffle
        dataset = pd.concat([phishing_df, legitimate_df], ignore_index=True)
        dataset = dataset.sample(frac=1).reset_index(drop=True)
        
        return dataset
    
    def _add_synthetic_variants(self, dataset: pd.DataFrame) -> pd.DataFrame:
        """Add synthetic phishing variants for data augmentation"""
        synthetic_urls = []
        
        # Get legitimate URLs to create variants
        legitimate_urls = dataset[dataset['label'] == 0]['url'].tolist()
        
        for url in legitimate_urls[:100]:  # Limit to first 100
            variants = self._generate_phishing_variants(url)
            for variant in variants:
                synthetic_urls.append({
                    'url': variant,
                    'label': 1,  # These are synthetic phishing URLs
                    'source': 'synthetic_generation'
                })
        
        # Add synthetic data
        if synthetic_urls:
            synthetic_df = pd.DataFrame(synthetic_urls)
            dataset = pd.concat([dataset, synthetic_df], ignore_index=True)
        
        return dataset
    
    def _generate_phishing_variants(self, url: str) -> List[str]:
        """Generate phishing variants of legitimate URLs"""
        variants = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Typosquatting variants
            typo_variants = [
                domain.replace('o', '0'),  # o -> 0
                domain.replace('e', '3'),  # e -> 3
                domain.replace('a', '@'),  # a -> @
                domain.replace('.com', '.co'),  # .com -> .co
                domain.replace('.com', '.net'),  # .com -> .net
                f"{domain}.security-update.com",  # subdomain variant
                f"secure-{domain}",  # prefix variant
                f"{domain}-verify.org"  # suffix variant
            ]
            
            for variant_domain in typo_variants:
                if variant_domain != domain and self._is_valid_domain(variant_domain):
                    variant_url = f"http://{variant_domain}{parsed.path}"
                    variants.append(variant_url)
        
        except Exception as e:
            logger.warning(f"Error generating variants for {url}: {e}")
        
        return variants[:3]  # Limit to 3 variants per URL
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and bool(parsed.scheme)
        except:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid"""
        return '.' in domain and len(domain) > 3 and len(domain) < 100
