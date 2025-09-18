package com.phishshieldai.android.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.phishshieldai.android.core.PhishingDetectionEngine
import com.phishshieldai.android.core.UrlExtractor
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import java.util.regex.Pattern
import javax.inject.Inject

@AndroidEntryPoint
class PhishShieldAccessibilityService : AccessibilityService() {
    
    companion object {
        private const val TAG = "PhishShieldAccessibility"
        private val URL_PATTERN = Pattern.compile(
            "(?i)\\b(?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»""''])"
        )
    }
    
    @Inject
    lateinit var detectionEngine: PhishingDetectionEngine
    
    @Inject
    lateinit var urlExtractor: UrlExtractor
    
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isServiceEnabled = false
    
    override fun onServiceConnected() {
        super.onServiceConnected()
        
        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_VIEW_CLICKED or
                        AccessibilityEvent.TYPE_VIEW_FOCUSED or
                        AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                        AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED
            
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                    AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            
            notificationTimeout = 100
        }
        
        serviceInfo = info
        isServiceEnabled = true
        
        Log.i(TAG, "PhishShield Accessibility Service connected and active")
    }
    
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!isServiceEnabled || event == null) return
        
        try {
            when (event.eventType) {
                AccessibilityEvent.TYPE_VIEW_CLICKED -> {
                    handleViewClicked(event)
                }
                AccessibilityEvent.TYPE_VIEW_FOCUSED -> {
                    handleViewFocused(event)
                }
                AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                    handleContentChanged(event)
                }
                AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                    handleTextChanged(event)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing accessibility event", e)
        }
    }
    
    private fun handleViewClicked(event: AccessibilityEvent) {
        // Extract URLs from clicked views
        val clickedNode = event.source
        if (clickedNode != null) {
            val urls = extractUrlsFromNode(clickedNode)
            urls.forEach { url ->
                Log.d(TAG, "URL clicked: $url")
                scanUrlInBackground(url, "click")
            }
        }
    }
    
    private fun handleViewFocused(event: AccessibilityEvent) {
        // Monitor focused elements that might contain URLs
        val focusedNode = event.source
        if (focusedNode != null && isUrlInputField(focusedNode)) {
            val text = focusedNode.text?.toString()
            if (!text.isNullOrBlank()) {
                val urls = extractUrlsFromText(text)
                urls.forEach { url ->
                    Log.d(TAG, "URL in focused field: $url")
                    scanUrlInBackground(url, "input")
                }
            }
        }
    }
    
    private fun handleContentChanged(event: AccessibilityEvent) {
        // Monitor for dynamically loaded content with URLs
        if (isRelevantApp(event.packageName?.toString())) {
            val rootNode = rootInActiveWindow
            if (rootNode != null) {
                val urls = extractUrlsFromNode(rootNode)
                urls.forEach { url ->
                    Log.d(TAG, "URL in content: $url")
                    scanUrlInBackground(url, "content")
                }
            }
        }
    }
    
    private fun handleTextChanged(event: AccessibilityEvent) {
        // Monitor text input for URLs being typed
        val changedText = event.text?.toString()
        if (!changedText.isNullOrBlank()) {
            val urls = extractUrlsFromText(changedText)
            urls.forEach { url ->
                if (url.length > 10) { // Only scan reasonably complete URLs
                    Log.d(TAG, "URL typed: $url")
                    scanUrlInBackground(url, "typing")
                }
            }
        }
    }
    
    private fun extractUrlsFromNode(node: AccessibilityNodeInfo): List<String> {
        val urls = mutableListOf<String>()
        
        // Check node text
        node.text?.toString()?.let { text ->
            urls.addAll(extractUrlsFromText(text))
        }
        
        // Check content description
        node.contentDescription?.toString()?.let { desc ->
            urls.addAll(extractUrlsFromText(desc))
        }
        
        // Check child nodes recursively
        for (i in 0 until node.childCount) {
            node.getChild(i)?.let { child ->
                urls.addAll(extractUrlsFromNode(child))
            }
        }
        
        return urls.distinct()
    }
    
    private fun extractUrlsFromText(text: String): List<String> {
        val urls = mutableListOf<String>()
        val matcher = URL_PATTERN.matcher(text)
        
        while (matcher.find()) {
            val url = matcher.group().trim()
            if (isValidUrl(url)) {
                urls.add(normalizeUrl(url))
            }
        }
        
        return urls
    }
    
    private fun isValidUrl(url: String): Boolean {
        return url.length > 7 && 
               (url.startsWith("http://") || 
                url.startsWith("https://") || 
                url.contains("."))
    }
    
    private fun normalizeUrl(url: String): String {
        return when {
            url.startsWith("http://") || url.startsWith("https://") -> url
            url.startsWith("www.") -> "https://$url"
            url.contains(".") -> "https://$url"
            else -> url
        }
    }
    
    private fun isUrlInputField(node: AccessibilityNodeInfo): Boolean {
        val className = node.className?.toString()?.lowercase() ?: ""
        val hint = node.hintText?.toString()?.lowercase() ?: ""
        val desc = node.contentDescription?.toString()?.lowercase() ?: ""
        
        return className.contains("edittext") &&
               (hint.contains("url") || hint.contains("link") || hint.contains("website") ||
                desc.contains("url") || desc.contains("link") || desc.contains("address"))
    }
    
    private fun isRelevantApp(packageName: String?): Boolean {
        if (packageName == null) return false
        
        val relevantApps = listOf(
            "com.android.chrome",
            "com.android.browser",
            "org.mozilla.firefox",
            "com.whatsapp",
            "com.facebook.katana",
            "com.instagram.android",
            "com.twitter.android",
            "com.linkedin.android",
            "com.google.android.gm", // Gmail
            "com.android.email",
            "com.google.android.apps.messaging", // Messages
            "com.android.mms"
        )
        
        return relevantApps.any { packageName.contains(it) }
    }
    
    private fun scanUrlInBackground(url: String, source: String) {
        serviceScope.launch {
            try {
                val scanResult = detectionEngine.scanUrl(url)
                
                if (scanResult.isMalicious) {
                    Log.w(TAG, "Malicious URL detected from $source: $url")
                    showPhishingWarning(url, scanResult, source)
                } else {
                    Log.d(TAG, "URL scan passed: $url")
                }
                
                // Store scan result
                storeScanResult(url, scanResult, source)
                
            } catch (e: Exception) {
                Log.e(TAG, "Error scanning URL: $url", e)
            }
        }
    }
    
    private fun showPhishingWarning(url: String, scanResult: Any, source: String) {
        // Send broadcast to show warning dialog
        val intent = Intent("com.phishshieldai.android.PHISHING_DETECTED").apply {
            putExtra("url", url)
            putExtra("source", source)
            putExtra("threat_level", scanResult.toString())
        }
        sendBroadcast(intent)
    }
    
    private fun storeScanResult(url: String, scanResult: Any, source: String) {
        // TODO: Store in Room database
        Log.d(TAG, "Storing scan result: $url -> $scanResult")
    }
    
    override fun onInterrupt() {
        Log.i(TAG, "PhishShield Accessibility Service interrupted")
        isServiceEnabled = false
    }
    
    override fun onDestroy() {
        super.onDestroy()
        isServiceEnabled = false
        serviceScope.cancel()
        Log.i(TAG, "PhishShield Accessibility Service destroyed")
    }
}