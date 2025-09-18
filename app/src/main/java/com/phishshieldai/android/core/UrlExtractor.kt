package com.phishshieldai.android.core

import android.util.Log
import java.net.URL
import java.util.regex.Pattern
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class UrlExtractor @Inject constructor() {
    
    companion object {
        private const val TAG = "UrlExtractor"
        
        private val URL_PATTERN = Pattern.compile(
            "(?i)\\b(?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»""''])"
        )
    }
    
    fun extractUrls(text: String): List<String> {
        val urls = mutableListOf<String>()
        val matcher = URL_PATTERN.matcher(text)
        
        while (matcher.find()) {
            val url = matcher.group().trim()
            if (isValidUrl(url)) {
                urls.add(normalizeUrl(url))
            }
        }
        
        return urls.distinct()
    }
    
    private fun isValidUrl(url: String): Boolean {
        return try {
            URL(url)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private fun normalizeUrl(url: String): String {
        return when {
            url.startsWith("http://") || url.startsWith("https://") -> url
            url.startsWith("www.") -> "https://$url"
            url.contains(".") -> "https://$url"
            else -> url
        }
    }
}
