package com.phishshieldai.android.ml

import android.content.Context
import android.util.Log
import com.phishshieldai.android.data.model.AnalysisResult
import com.phishshieldai.android.data.model.ThreatLevel
import dagger.hilt.android.qualifiers.ApplicationContext
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.io.IOException
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class PhishingMLModel @Inject constructor(
    @ApplicationContext private val context: Context
) {
    
    companion object {
        private const val TAG = "PhishingMLModel"
        private const val MODEL_FILE = "models/phishing_detector.tflite"
        private const val INPUT_SIZE = 48 // Enhanced: 43 original + 5 threat intel features
    }
    
    private var interpreter: Interpreter? = null
    private var isModelLoaded = false
    
    init {
        loadModel()
    }
    
    fun predictWithThreatIntel(
        url: String, 
        lexicalResult: AnalysisResult,
        threatIntelResult: AnalysisResult,
        reputationResult: AnalysisResult,
        contentResult: AnalysisResult
    ): AnalysisResult {
        
        if (!isModelLoaded) {
            Log.w(TAG, "Model not loaded, using enhanced fallback with threat intel")
            return getEnhancedFallbackPrediction(lexicalResult, threatIntelResult, reputationResult, contentResult)
        }
        
        try {
            // Extract enhanced features including threat intelligence
            val features = extractEnhancedFeatures(url, lexicalResult, threatIntelResult, reputationResult, contentResult)
            
            // Prepare input tensor
            val inputBuffer = ByteBuffer.allocateDirect(INPUT_SIZE * 4) // 4 bytes per float
            inputBuffer.order(ByteOrder.nativeOrder())
            features.forEach { inputBuffer.putFloat(it) }
            
            // Prepare output tensor
            val outputBuffer = ByteBuffer.allocateDirect(4) // Single float output
            outputBuffer.order(ByteOrder.nativeOrder())
            
            // Run inference
            interpreter?.run(inputBuffer, outputBuffer)
            outputBuffer.rewind()
            
            val prediction = outputBuffer.float
            
            // Enhanced threat level calculation considering threat intel
            val enhancedScore = combineWithThreatIntel(prediction, threatIntelResult.confidence)
            
            val threatLevel = when {
                enhancedScore >= 0.8f -> ThreatLevel.CRITICAL
                enhancedScore >= 0.6f -> ThreatLevel.HIGH
                enhancedScore >= 0.4f -> ThreatLevel.MEDIUM
                else -> ThreatLevel.LOW
            }
            
            Log.d(TAG, "Enhanced ML prediction: $enhancedScore (with threat intel)")
            
            return AnalysisResult(
                isMalicious = enhancedScore >= 0.5f,
                threatLevel = threatLevel,
                confidence = enhancedScore,
                details = mapOf(
                    "ml_prediction" to prediction,
                    "threat_intel_boost" to threatIntelResult.confidence,
                    "combined_score" to enhancedScore
                )
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Enhanced ML prediction failed", e)
            return getEnhancedFallbackPrediction(lexicalResult, threatIntelResult, reputationResult, contentResult)
        }
    }
    
    fun predict(
        url: String, 
        lexicalResult: AnalysisResult,
        reputationResult: AnalysisResult,
        contentResult: AnalysisResult
    ): AnalysisResult {
        
        if (!isModelLoaded) {
            Log.w(TAG, "Model not loaded, using fallback heuristics")
            return getFallbackPrediction(lexicalResult, reputationResult, contentResult)
        }
        
        try {
            // Extract features for ML model
            val features = extractFeatures(url, lexicalResult, reputationResult, contentResult)
            
            // Prepare input buffer
            val inputBuffer = ByteBuffer.allocateDirect(4 * INPUT_SIZE)
            inputBuffer.order(ByteOrder.nativeOrder())
            
            features.forEach { feature ->
                inputBuffer.putFloat(feature)
            }
            
            // Prepare output buffer
            val outputBuffer = ByteBuffer.allocateDirect(4)
            outputBuffer.order(ByteOrder.nativeOrder())
            
            // Run inference
            interpreter?.run(inputBuffer, outputBuffer)
            
            // Get prediction
            outputBuffer.rewind()
            val prediction = outputBuffer.float
            
            // Convert to threat level
            val threatLevel = when {
                prediction >= 0.8f -> ThreatLevel.HIGH
                prediction >= 0.5f -> ThreatLevel.MEDIUM
                else -> ThreatLevel.LOW
            }
            
            return AnalysisResult(
                threatLevel = threatLevel,
                confidence = prediction,
                details = "ML model prediction: ${(prediction * 100).toInt()}% confidence"
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "ML inference failed", e)
            return getFallbackPrediction(lexicalResult, reputationResult, contentResult)
        }
    }
    
    private fun loadModel() {
        try {
            val modelBuffer = loadModelFile()
            interpreter = Interpreter(modelBuffer)
            isModelLoaded = true
            Log.i(TAG, "TensorFlow Lite model loaded successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load ML model", e)
            isModelLoaded = false
        }
    }
    
    private fun loadModelFile(): MappedByteBuffer {
        val assetFileDescriptor = context.assets.openFd(MODEL_FILE)
        val inputStream = FileInputStream(assetFileDescriptor.fileDescriptor)
        val fileChannel = inputStream.channel
        val startOffset = assetFileDescriptor.startOffset
        val declaredLength = assetFileDescriptor.declaredLength
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
    }
    
    private fun extractFeatures(
        url: String,
        lexicalResult: AnalysisResult,
        reputationResult: AnalysisResult,
        contentResult: AnalysisResult
    ): FloatArray {
        val features = FloatArray(INPUT_SIZE)
        var index = 0
        
        try {
            val parsedUrl = URL(url)
            
            // Basic URL features (8 features)
            features[index++] = url.length.toFloat()
            features[index++] = parsedUrl.host?.length?.toFloat() ?: 0f
            features[index++] = parsedUrl.path?.length?.toFloat() ?: 0f
            features[index++] = parsedUrl.query?.length?.toFloat() ?: 0f
            features[index++] = parsedUrl.host?.count { it == '.' }?.toFloat() ?: 0f
            features[index++] = if (parsedUrl.protocol == "https") 1f else 0f
            features[index++] = if (parsedUrl.port != -1) 1f else 0f
            features[index++] = if (parsedUrl.ref != null) 1f else 0f
            
            // Lexical features (12 features)
            features[index++] = url.count { it == '-' }.toFloat()
            features[index++] = url.count { it == '_' }.toFloat()
            features[index++] = url.count { it == '.' }.toFloat()
            features[index++] = url.count { it == '/' }.toFloat()
            features[index++] = url.count { it == '?' }.toFloat()
            features[index++] = url.count { it == '=' }.toFloat()
            features[index++] = url.count { it == '&' }.toFloat()
            
            val digitCount = url.count { it.isDigit() }
            features[index++] = digitCount.toFloat() / url.length
            
            val alphaCount = url.count { it.isLetter() }
            features[index++] = alphaCount.toFloat() / url.length
            
            features[index++] = calculateEntropy(url)
            
            val words = url.split(Regex("[^a-zA-Z]+")).filter { it.isNotEmpty() }
            features[index++] = words.maxOfOrNull { it.length }?.toFloat() ?: 0f
            features[index++] = if (words.isNotEmpty()) words.sumOf { it.length }.toFloat() / words.size else 0f
            
            // Domain features (8 features)
            val domain = parsedUrl.host?.lowercase() ?: ""
            features[index++] = if (isIPAddress(domain)) 1f else 0f
            features[index++] = if (hasSuspiciousTLD(domain)) 1f else 0f
            features[index++] = if (isURLShortener(domain)) 1f else 0f
            features[index++] = if (domain.any { it.isDigit() }) 1f else 0f
            features[index++] = calculateEntropy(domain.replace(".", ""))
            features[index++] = domain.count { it == '.' }.toFloat()
            features[index++] = domain.length.toFloat()
            features[index++] = parsedUrl.host?.substringAfterLast('.')?.length?.toFloat() ?: 0f
            
            // Path and query features (6 features)
            val path = parsedUrl.path?.lowercase() ?: ""
            features[index++] = path.count { it == '/' }.toFloat()
            features[index++] = if (path.substringAfterLast('/').contains('.')) 1f else 0f
            features[index++] = countSuspiciousKeywords(path)
            
            val query = parsedUrl.query?.lowercase() ?: ""
            val queryParams = if (query.isNotEmpty()) query.split('&').size else 0
            features[index++] = queryParams.toFloat()
            features[index++] = countSuspiciousKeywords(query)
            features[index++] = if (query.contains('%')) 1f else 0f
            
            // Security features (4 features)
            features[index++] = if (parsedUrl.protocol == "https") 1f else 0f
            features[index++] = if (parsedUrl.protocol == "http") 1f else 0f
            features[index++] = if (parsedUrl.port != -1 && parsedUrl.port !in listOf(80, 443)) 1f else 0f
            features[index++] = if (url.contains('@')) 1f else 0f
            
            // Suspicious pattern features (5 features)
            features[index++] = countBrandMentions(url)
            features[index++] = countSuspiciousKeywords(url)
            features[index++] = if (hasHomographChars(url)) 1f else 0f
            features[index++] = countRedirectIndicators(url)
            features[index++] = (url.count { it == ':' } - 1).toFloat() // Multiple domains
            
        } catch (e: Exception) {
            Log.w(TAG, "Error extracting features from URL: $url", e)
            // Fill remaining features with zeros
            for (i in index until INPUT_SIZE) {
                features[i] = 0f
            }
        }
        
        return features
    }
    
    private fun extractEnhancedFeatures(
        url: String,
        lexicalResult: AnalysisResult,
        threatIntelResult: AnalysisResult,
        reputationResult: AnalysisResult,
        contentResult: AnalysisResult
    ): FloatArray {
        val domain = try {
            URL(url).host
        } catch (e: Exception) {
            url
        }
        
        val path = try {
            URL(url).path
        } catch (e: Exception) {
            ""
        }
        
        return floatArrayOf(
            // Original 43 features
            *extractFeatures(url, lexicalResult, reputationResult, contentResult),
            
            // Enhanced threat intelligence features (5 additional features)
            threatIntelResult.confidence,  // Feature 44: Threat intel confidence
            if (threatIntelResult.isMalicious) 1.0f else 0.0f,  // Feature 45: Threat intel verdict
            threatIntelResult.details.get("reputation_score")?.toString()?.toFloatOrNull() ?: 0.0f,  // Feature 46: Reputation score
            threatIntelResult.details.get("threat_sources_count")?.toString()?.toFloatOrNull() ?: 0.0f,  // Feature 47: Number of threat sources
            when (threatIntelResult.threatLevel) {  // Feature 48: Threat level numeric
                ThreatLevel.CRITICAL -> 1.0f
                ThreatLevel.HIGH -> 0.8f
                ThreatLevel.MEDIUM -> 0.6f
                ThreatLevel.LOW -> 0.4f
                else -> 0.0f
            }
        )
    }
    
    private fun combineWithThreatIntel(mlPrediction: Float, threatIntelConfidence: Float): Float {
        // Weighted combination of ML prediction and threat intelligence
        val mlWeight = 0.7f
        val threatIntelWeight = 0.3f
        
        // If threat intel has high confidence, give it more weight
        val adjustedThreatIntelWeight = if (threatIntelConfidence > 0.8f) 0.5f else threatIntelWeight
        val adjustedMlWeight = 1.0f - adjustedThreatIntelWeight
        
        return mlPrediction * adjustedMlWeight + threatIntelConfidence * adjustedThreatIntelWeight
    }
    
    private fun getEnhancedFallbackPrediction(
        lexicalResult: AnalysisResult,
        threatIntelResult: AnalysisResult,
        reputationResult: AnalysisResult,
        contentResult: AnalysisResult
    ): AnalysisResult {
        // Enhanced fallback that prioritizes threat intelligence
        val threatIntelWeight = 0.4f
        val lexicalWeight = 0.25f
        val reputationWeight = 0.2f
        val contentWeight = 0.15f
        
        val combinedScore = (
            threatIntelResult.confidence * threatIntelWeight +
            lexicalResult.confidence * lexicalWeight +
            reputationResult.confidence * reputationWeight +
            contentResult.confidence * contentWeight
        )
        
        // If threat intel indicates malicious with high confidence, boost score
        val enhancedScore = if (threatIntelResult.isMalicious && threatIntelResult.confidence > 0.7f) {
            kotlin.math.max(combinedScore, 0.8f)
        } else {
            combinedScore
        }
        
        val threatLevel = when {
            enhancedScore >= 0.8f -> ThreatLevel.CRITICAL
            enhancedScore >= 0.6f -> ThreatLevel.HIGH
            enhancedScore >= 0.4f -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return AnalysisResult(
            isMalicious = enhancedScore >= 0.5f,
            threatLevel = threatLevel,
            confidence = enhancedScore,
            details = mapOf(
                "fallback_prediction" to true,
                "threat_intel_weight" to threatIntelWeight,
                "ml_model_unavailable" to true
            )
        )
    }
    
    private fun getFallbackPrediction(
        lexicalResult: AnalysisResult,
        reputationResult: AnalysisResult,
        contentResult: AnalysisResult
    ): AnalysisResult {
        val combinedScore = (lexicalResult.confidence + reputationResult.confidence + contentResult.confidence) / 3
        
        val threatLevel = when {
            combinedScore >= 0.7f -> ThreatLevel.HIGH
            combinedScore >= 0.4f -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return AnalysisResult(
            isMalicious = combinedScore >= 0.5f,
            threatLevel = threatLevel,
            confidence = combinedScore,
            details = mapOf("fallback_heuristic_prediction" to true)
        )
    }
    
    // Helper functions for feature extraction
    private fun calculateEntropy(text: String): Float {
        if (text.isEmpty()) return 0f
        
        val charCounts = text.groupingBy { it }.eachCount()
        val length = text.length.toFloat()
        
        return charCounts.values.sumOf { count ->
            val probability = count / length
            if (probability > 0) -probability * kotlin.math.ln(probability) / kotlin.math.ln(2.0) else 0.0
        }.toFloat()
    }
    
    private fun isIPAddress(domain: String): Boolean {
        return domain.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""))
    }
    
    private fun hasSuspiciousTLD(domain: String): Boolean {
        val suspiciousTLDs = listOf(".tk", ".ml", ".ga", ".cf", ".icu", ".top", ".click")
        return suspiciousTLDs.any { domain.endsWith(it) }
    }
    
    private fun isURLShortener(domain: String): Boolean {
        val shorteners = listOf("bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl")
        return shorteners.any { domain.contains(it) }
    }
    
    private fun countSuspiciousKeywords(text: String): Float {
        val keywords = listOf(
            "secure", "verify", "update", "suspend", "limited", "expired",
            "confirm", "validate", "urgent", "immediate", "action", "required"
        )
        return keywords.count { text.contains(it, ignoreCase = true) }.toFloat()
    }
    
    private fun countBrandMentions(text: String): Float {
        val brands = listOf("paypal", "amazon", "google", "microsoft", "apple", "facebook")
        return brands.count { text.contains(it, ignoreCase = true) }.toFloat()
    }
    
    private fun hasHomographChars(text: String): Boolean {
        val latinChars = text.count { it.code < 128 }
        val nonLatinChars = text.length - latinChars
        return nonLatinChars > 0 && (nonLatinChars.toFloat() / text.length) > 0.1
    }
    
    private fun countRedirectIndicators(text: String): Float {
        val redirectParams = listOf("redirect", "goto", "url", "link", "target", "continue")
        return redirectParams.count { text.contains(it, ignoreCase = true) }.toFloat()
    }
}
