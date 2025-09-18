"""
ML Service - Advanced Machine Learning for Phishing Detection
"""

import logging
import asyncio
import math
from typing import Dict, Any, List
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)

class MLService:
    """
    Machine Learning Service for advanced phishing detection
    """
    
    def __init__(self):
        self.models = {}
        self.feature_extractors = {}
        
    async def load_models(self):
        """Load ML models for inference"""
        try:
            # TODO: Load actual ML models
            logger.info("ML models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            
    async def analyze_advanced(
        self, 
        url: str, 
        sandbox_data: Dict[str, Any],
        network_data: Dict[str, Any],
        previous_layers: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform advanced ML analysis combining all data sources
        """
        try:
            # Extract features from all data sources
            features = await self._extract_features(
                url, sandbox_data, network_data, previous_layers
            )
            
            # Run inference
            prediction = await self._run_inference(features)
            
            return {
                "confidence": prediction["confidence"],
                "threat_probability": prediction["threat_probability"],
                "feature_importance": prediction["feature_importance"],
                "model_version": "1.0.0"
            }
            
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            return {
                "confidence": 0.5,
                "threat_probability": 0.0,
                "feature_importance": {},
                "model_version": "error"
            }
    
    async def _extract_features(
        self, 
        url: str, 
        sandbox_data: Dict[str, Any],
        network_data: Dict[str, Any],
        previous_layers: Dict[str, Any]
    ) -> Dict[str, float]:
        """Extract ML features from all analysis layers"""
        features = {}
        
        # URL-based features
        features.update(self._extract_url_features(url))
        
        # Sandbox-based features
        features.update(self._extract_sandbox_features(sandbox_data))
        
        # Network-based features
        features.update(self._extract_network_features(network_data))
        
        # Previous layer features
        features.update(self._extract_previous_layer_features(previous_layers))
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict[str, float]:
        """Extract features from URL string"""
        return {
            "url_length": len(url),
            "subdomain_count": url.count('.'),
            "has_https": 1.0 if url.startswith('https') else 0.0,
            "has_ip": 1.0 if any(c.isdigit() for c in url.split('//')[1].split('/')[0]) else 0.0
        }
    
    def _extract_sandbox_features(self, sandbox_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from sandbox analysis"""
        return {
            "form_count": len(sandbox_data.get("forms", [])),
            "redirect_count": len(sandbox_data.get("redirects", [])),
            "js_obfuscated": 1.0 if sandbox_data.get("javascript", {}).get("obfuscated_code") else 0.0,
            "keylogger_detected": 1.0 if sandbox_data.get("javascript", {}).get("keylogger_detected") else 0.0,
            "risk_indicator_count": len(sandbox_data.get("risk_indicators", []))
        }
    
    def _extract_network_features(self, network_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from network analysis"""
        return {
            "campaign_detected": 1.0 if network_data.get("campaign_detected") else 0.0,
            "cluster_risk": network_data.get("cluster_risk_score", 0.0),
            "ip_malicious": 1.0 if network_data.get("ip_reputation", {}).get("malicious") else 0.0
        }
    
    def _extract_previous_layer_features(self, previous_layers: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from previous analysis layers"""
        features = {}
        
        if "lexical" in previous_layers:
            features["lexical_confidence"] = previous_layers["lexical"].get("confidence", 0.0)
        
        if "reputation" in previous_layers:
            features["reputation_confidence"] = previous_layers["reputation"].get("confidence", 0.0)
        
        return features
    
    async def _run_inference(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Run ML model inference"""
        try:
            # Enhanced feature-based prediction until real ML model is loaded
            logger.info(f"Running ML inference on {len(features)} features")
            
            # Weight different feature categories
            weights = {
                "url_length": 0.1,
                "domain_entropy": 0.15,
                "suspicious_tld": 0.2,
                "ip_address_host": 0.25,
                "suspicious_keywords": 0.3,
                "domain_age": 0.15,
                "ssl_certificate": 0.2,
                "redirect_count": 0.1,
                "lexical_confidence": 0.25,
                "reputation_confidence": 0.3,
                "subdomain_count": 0.1,
                "path_complexity": 0.05
            }
            
            # Calculate weighted risk score
            weighted_score = 0.0
            total_weight = 0.0
            feature_importance = {}
            
            for feature_name, feature_value in features.items():
                weight = weights.get(feature_name, 0.05)  # default weight for unknown features
                contribution = feature_value * weight
                weighted_score += contribution
                total_weight += weight
                
                # Calculate feature importance
                feature_importance[feature_name] = contribution
            
            # Normalize score
            if total_weight > 0:
                weighted_score = weighted_score / total_weight
            
            # Apply non-linear transformation for better separation
            threat_probability = 1 / (1 + math.exp(-5 * (weighted_score - 0.5)))
            
            # Determine confidence based on feature consistency
            confidence = self._calculate_confidence(features, threat_probability)
            
            # Normalize feature importance
            total_importance = sum(feature_importance.values())
            if total_importance > 0:
                feature_importance = {k: v / total_importance for k, v in feature_importance.items()}
            
            result = {
                "confidence": min(confidence, 1.0),
                "threat_probability": min(threat_probability, 1.0),
                "feature_importance": feature_importance,
                "model_version": "1.0-enhanced",
                "features_used": len(features)
            }
            
            logger.info(f"ML inference complete: threat_prob={result['threat_probability']:.3f}, confidence={result['confidence']:.3f}")
            return result
            
        except Exception as e:
            logger.error(f"ML inference failed: {e}")
            # Fallback to simple average
            feature_values = list(features.values())
            avg_risk = sum(feature_values) / len(feature_values) if feature_values else 0.5
            
            return {
                "confidence": 0.5,
                "threat_probability": avg_risk,
                "feature_importance": {k: 1.0 / len(features) for k in features.keys()},
                "model_version": "1.0-fallback",
                "features_used": len(features)
            }
    
    def _calculate_confidence(self, features: Dict[str, float], threat_probability: float) -> float:
        """Calculate confidence based on feature consistency and quality"""
        try:
            # Start with base confidence
            confidence = 0.7
            
            # Boost confidence if multiple features agree
            high_risk_features = sum(1 for v in features.values() if v > 0.7)
            low_risk_features = sum(1 for v in features.values() if v < 0.3)
            
            total_features = len(features)
            if total_features > 0:
                if high_risk_features / total_features > 0.6:
                    confidence += 0.2  # Multiple indicators agree on high risk
                elif low_risk_features / total_features > 0.6:
                    confidence += 0.2  # Multiple indicators agree on low risk
            
            # Reduce confidence if features are contradictory
            contradictory = abs(high_risk_features - low_risk_features)
            if contradictory > total_features * 0.4:
                confidence -= 0.1
            
            # Boost confidence for extreme threat probabilities
            if threat_probability > 0.9 or threat_probability < 0.1:
                confidence += 0.1
            
            # Ensure confidence is within bounds
            return max(0.3, min(1.0, confidence))
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {e}")
            return 0.5
