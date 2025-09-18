"""
Sandbox Service - Layer 6 Dynamic Behavioral Analysis
Uses headless browsers to analyze URL behavior in isolated environment
"""

import asyncio
import logging
import json
import time
from typing import Dict, List, Any, Optional
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from datetime import datetime
import hashlib
import os

from app.core.config import settings

logger = logging.getLogger(__name__)

class SandboxService:
    """
    URL Sandbox Analysis Service
    Performs dynamic analysis of URLs in isolated browser environment
    """
    
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.max_concurrent = settings.SANDBOX_MAX_CONCURRENT
        self.timeout = settings.SANDBOX_TIMEOUT
        self.screenshots_enabled = settings.SANDBOX_SCREENSHOTS
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
    async def initialize(self):
        """Initialize the sandbox service"""
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--no-first-run',
                    '--disable-extensions',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding'
                ]
            )
            logger.info("Sandbox service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize sandbox service: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup sandbox resources"""
        try:
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("Sandbox service cleaned up")
        except Exception as e:
            logger.error(f"Error during sandbox cleanup: {e}")
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive sandbox analysis of a URL
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dict containing analysis results
        """
        async with self.semaphore:
            return await self._analyze_url_impl(url)
    
    async def _analyze_url_impl(self, url: str) -> Dict[str, Any]:
        """Internal URL analysis implementation"""
        start_time = time.time()
        analysis_id = hashlib.md5(f"{url}{start_time}".encode()).hexdigest()[:8]
        
        logger.info(f"Starting sandbox analysis {analysis_id} for URL: {url}")
        
        result = {
            "analysis_id": analysis_id,
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
            "page_title": None,
            "final_url": url,
            "redirects": [],
            "forms": [],
            "javascript": {
                "keylogger_detected": False,
                "obfuscated_code": False,
                "suspicious_functions": [],
                "external_scripts": []
            },
            "network_requests": [],
            "screenshots": [],
            "risk_indicators": [],
            "errors": [],
            "execution_time": 0.0
        }
        
        context = None
        page = None
        
        try:
            # Create new browser context with security settings
            context = await self.browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
                java_script_enabled=True
            )
            
            page = await context.new_page()
            
            # Set up event listeners
            await self._setup_page_listeners(page, result)
            
            # Navigate to URL and analyze
            await self._navigate_and_analyze(page, url, result, analysis_id)
            
        except PlaywrightTimeoutError:
            logger.warning(f"Timeout during analysis {analysis_id}")
            result["errors"].append("Navigation timeout")
            result["risk_indicators"].append("Slow loading page (potential stalling)")
            
        except Exception as e:
            logger.error(f"Error during sandbox analysis {analysis_id}: {e}")
            result["errors"].append(f"Analysis error: {str(e)}")
            
        finally:
            # Cleanup
            if page:
                await page.close()
            if context:
                await context.close()
            
            result["execution_time"] = time.time() - start_time
            logger.info(f"Sandbox analysis {analysis_id} completed in {result['execution_time']:.2f}s")
            
        return result
    
    async def _setup_page_listeners(self, page, result: Dict[str, Any]):
        """Set up page event listeners for monitoring"""
        
        # Monitor network requests
        async def handle_request(request):
            result["network_requests"].append({
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type
            })
        
        # Monitor responses for redirects
        async def handle_response(response):
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get("location")
                if location:
                    result["redirects"].append({
                        "from": response.url,
                        "to": location,
                        "status": response.status
                    })
        
        # Monitor console for JavaScript errors/warnings
        async def handle_console(msg):
            if msg.type in ["error", "warning"]:
                result["javascript"]["suspicious_functions"].append({
                    "type": msg.type,
                    "text": msg.text
                })
        
        page.on("request", handle_request)
        page.on("response", handle_response)
        page.on("console", handle_console)
    
    async def _navigate_and_analyze(self, page, url: str, result: Dict[str, Any], analysis_id: str):
        """Navigate to URL and perform analysis"""
        
        # Navigate to the URL
        response = await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
        
        # Get final URL after redirects
        result["final_url"] = page.url
        
        # Get page title
        try:
            result["page_title"] = await page.title()
        except:
            pass
        
        # Take screenshot if enabled
        if self.screenshots_enabled:
            screenshot_path = f"/app/screenshots/{analysis_id}.png"
            try:
                await page.screenshot(path=screenshot_path, full_page=True)
                result["screenshots"].append(screenshot_path)
            except Exception as e:
                logger.warning(f"Failed to take screenshot: {e}")
        
        # Analyze forms
        await self._analyze_forms(page, result)
        
        # Analyze JavaScript
        await self._analyze_javascript(page, result)
        
        # Check for phishing indicators
        await self._check_phishing_indicators(page, result)
        
        # Wait a bit more to capture any delayed JavaScript behavior
        await asyncio.sleep(2)
    
    async def _analyze_forms(self, page, result: Dict[str, Any]):
        """Analyze forms on the page"""
        try:
            forms = await page.evaluate("""
                () => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    return forms.map(form => {
                        const inputs = Array.from(form.querySelectorAll('input'));
                        return {
                            action: form.action || window.location.href,
                            method: form.method || 'GET',
                            fields: inputs.map(input => ({
                                type: input.type,
                                name: input.name,
                                placeholder: input.placeholder,
                                required: input.required
                            }))
                        };
                    });
                }
            """)
            
            result["forms"] = forms
            
            # Check for suspicious forms
            for form in forms:
                fields = [field["name"].lower() for field in form["fields"]]
                suspicious_fields = ["password", "ssn", "social", "credit", "card", "cvv", "pin"]
                
                if any(suspicious in " ".join(fields) for suspicious in suspicious_fields):
                    result["risk_indicators"].append("Form collecting sensitive information detected")
                
                # Check if form action goes to different domain
                if form["action"] and not form["action"].startswith(page.url.split("/")[0:3]):
                    result["risk_indicators"].append("Form submits to external domain")
                    
        except Exception as e:
            logger.warning(f"Form analysis failed: {e}")
    
    async def _analyze_javascript(self, page, result: Dict[str, Any]):
        """Analyze JavaScript behavior"""
        try:
            # Check for common obfuscation techniques
            js_analysis = await page.evaluate("""
                () => {
                    const scripts = Array.from(document.querySelectorAll('script'));
                    let obfuscated = false;
                    let keylogger = false;
                    let suspiciousFunctions = [];
                    let externalScripts = [];
                    
                    scripts.forEach(script => {
                        if (script.src) {
                            externalScripts.push(script.src);
                        }
                        
                        const content = script.textContent || script.innerHTML;
                        if (content) {
                            // Check for obfuscation
                            if (content.includes('eval(') || 
                                content.includes('unescape(') ||
                                content.includes('String.fromCharCode') ||
                                content.length > 1000 && content.split('\\n').length < 10) {
                                obfuscated = true;
                            }
                            
                            // Check for keylogger patterns
                            if (content.includes('keydown') || 
                                content.includes('keypress') || 
                                content.includes('onkeydown')) {
                                keylogger = true;
                            }
                            
                            // Check for suspicious functions
                            const suspiciousPatterns = [
                                'document.write(',
                                'innerHTML',
                                'createElement(',
                                'appendChild(',
                                'location.href',
                                'window.open('
                            ];
                            
                            suspiciousPatterns.forEach(pattern => {
                                if (content.includes(pattern)) {
                                    suspiciousFunctions.push(pattern);
                                }
                            });
                        }
                    });
                    
                    return {
                        obfuscated,
                        keylogger,
                        suspiciousFunctions: [...new Set(suspiciousFunctions)],
                        externalScripts,
                        scriptCount: scripts.length
                    };
                }
            """)
            
            result["javascript"].update(js_analysis)
            
            if js_analysis["obfuscated"]:
                result["risk_indicators"].append("Obfuscated JavaScript code detected")
            
            if js_analysis["keylogger"]:
                result["risk_indicators"].append("Potential keylogger behavior detected")
                
        except Exception as e:
            logger.warning(f"JavaScript analysis failed: {e}")
    
    async def _check_phishing_indicators(self, page, result: Dict[str, Any]):
        """Check for common phishing indicators"""
        try:
            indicators = await page.evaluate("""
                () => {
                    const indicators = [];
                    
                    // Check for fake security badges
                    const securityImages = document.querySelectorAll('img[src*="secure"], img[src*="ssl"], img[src*="verified"]');
                    if (securityImages.length > 0) {
                        indicators.push('Security badge images detected');
                    }
                    
                    // Check for urgency language
                    const text = document.body.textContent.toLowerCase();
                    const urgentWords = ['urgent', 'immediate', 'suspend', 'expired', 'verify now', 'act now'];
                    urgentWords.forEach(word => {
                        if (text.includes(word)) {
                            indicators.push(`Urgency language detected: ${word}`);
                        }
                    });
                    
                    // Check for misleading URLs in links
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    links.forEach(link => {
                        const href = link.href.toLowerCase();
                        const text = link.textContent.toLowerCase();
                        
                        if (text.includes('paypal') && !href.includes('paypal.com')) {
                            indicators.push('Misleading PayPal link detected');
                        }
                        if (text.includes('amazon') && !href.includes('amazon.com')) {
                            indicators.push('Misleading Amazon link detected');
                        }
                        if (text.includes('google') && !href.includes('google.com')) {
                            indicators.push('Misleading Google link detected');
                        }
                    });
                    
                    return indicators;
                }
            """)
            
            result["risk_indicators"].extend(indicators)
            
        except Exception as e:
            logger.warning(f"Phishing indicator check failed: {e}")

# Global sandbox service instance
sandbox_service = SandboxService()
