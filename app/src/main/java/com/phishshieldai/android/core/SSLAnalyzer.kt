package com.phishshieldai.android.core

import android.util.Log
import java.net.URL
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * SSL Analyzer for detecting suspicious SSL certificates and connections
 * Used to identify potential phishing sites with invalid or suspicious certificates
 */
class SSLAnalyzer {

    companion object {
        private const val TAG = "SSLAnalyzer"
        private const val CERT_EXPIRY_WARNING_DAYS = 30
    }

    data class SSLAnalysisResult(
        val isSecure: Boolean,
        val certificateValid: Boolean,
        val issuerTrusted: Boolean,
        val domainMatches: Boolean,
        val expiryValid: Boolean,
        val riskScore: Int, // 0-100, higher = more risky
        val warnings: List<String>,
        val certificateInfo: CertificateInfo?
    )

    data class CertificateInfo(
        val subject: String,
        val issuer: String,
        val validFrom: Date,
        val validTo: Date,
        val serialNumber: String,
        val signatureAlgorithm: String
    )

    /**
     * Analyzes SSL certificate and connection for a given URL
     */
    fun analyzeSSL(urlString: String): SSLAnalysisResult {
        try {
            val url = URL(urlString)
            
            // Only analyze HTTPS URLs
            if (url.protocol != "https") {
                return SSLAnalysisResult(
                    isSecure = false,
                    certificateValid = false,
                    issuerTrusted = false,
                    domainMatches = false,
                    expiryValid = false,
                    riskScore = 100,
                    warnings = listOf("URL is not using HTTPS protocol"),
                    certificateInfo = null
                )
            }

            val connection = url.openConnection() as HttpsURLConnection
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            
            // Get certificate chain
            connection.connect()
            val certificates = connection.serverCertificates
            connection.disconnect()

            if (certificates.isEmpty()) {
                return createFailureResult("No certificates found")
            }

            val cert = certificates[0] as X509Certificate
            return analyzeCertificate(cert, url.host)

        } catch (e: Exception) {
            Log.e(TAG, "SSL Analysis failed", e)
            return createFailureResult("SSL analysis failed: ${e.message}")
        }
    }

    /**
     * Analyzes an X509 certificate for security issues
     */
    private fun analyzeCertificate(cert: X509Certificate, hostname: String): SSLAnalysisResult {
        val warnings = mutableListOf<String>()
        var riskScore = 0

        // Check certificate validity period
        val now = Date()
        val expiryValid = try {
            cert.checkValidity()
            true
        } catch (e: Exception) {
            warnings.add("Certificate is expired or not yet valid")
            riskScore += 40
            false
        }

        // Check if certificate is expiring soon
        val daysUntilExpiry = TimeUnit.MILLISECONDS.toDays(cert.notAfter.time - now.time)
        if (daysUntilExpiry < CERT_EXPIRY_WARNING_DAYS && expiryValid) {
            warnings.add("Certificate expires in $daysUntilExpiry days")
            riskScore += 10
        }

        // Check domain matching
        val domainMatches = checkDomainMatch(cert, hostname)
        if (!domainMatches) {
            warnings.add("Certificate domain does not match hostname")
            riskScore += 30
        }

        // Check issuer trust
        val issuerTrusted = checkIssuerTrust(cert)
        if (!issuerTrusted) {
            warnings.add("Certificate issued by untrusted or unknown CA")
            riskScore += 25
        }

        // Check for weak signature algorithms
        if (isWeakSignatureAlgorithm(cert.sigAlgName)) {
            warnings.add("Certificate uses weak signature algorithm: ${cert.sigAlgName}")
            riskScore += 15
        }

        // Check for suspicious certificate attributes
        val suspiciousAttributes = checkSuspiciousAttributes(cert)
        warnings.addAll(suspiciousAttributes)
        riskScore += suspiciousAttributes.size * 10

        val certificateInfo = CertificateInfo(
            subject = cert.subjectDN.name,
            issuer = cert.issuerDN.name,
            validFrom = cert.notBefore,
            validTo = cert.notAfter,
            serialNumber = cert.serialNumber.toString(),
            signatureAlgorithm = cert.sigAlgName
        )

        return SSLAnalysisResult(
            isSecure = riskScore < 50,
            certificateValid = expiryValid,
            issuerTrusted = issuerTrusted,
            domainMatches = domainMatches,
            expiryValid = expiryValid,
            riskScore = minOf(riskScore, 100),
            warnings = warnings,
            certificateInfo = certificateInfo
        )
    }

    /**
     * Checks if certificate domain matches the hostname
     */
    private fun checkDomainMatch(cert: X509Certificate, hostname: String): Boolean {
        try {
            // Check subject common name
            val subjectDN = cert.subjectDN.name
            val cn = extractCommonName(subjectDN)
            
            if (cn != null && (cn == hostname || isWildcardMatch(cn, hostname))) {
                return true
            }

            // Check Subject Alternative Names
            val sanCollection = cert.subjectAlternativeNames
            sanCollection?.forEach { san ->
                if (san.size >= 2 && san[0] == 2) { // DNS name
                    val dnsName = san[1] as String
                    if (dnsName == hostname || isWildcardMatch(dnsName, hostname)) {
                        return true
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking domain match", e)
        }
        return false
    }

    private fun extractCommonName(dn: String): String? {
        val cnPattern = "CN=([^,]+)".toRegex()
        return cnPattern.find(dn)?.groupValues?.get(1)
    }

    private fun isWildcardMatch(pattern: String, hostname: String): Boolean {
        if (!pattern.startsWith("*.")) return false
        val domain = pattern.substring(2)
        return hostname.endsWith(".$domain") || hostname == domain
    }

    /**
     * Checks if the certificate issuer is trusted
     */
    private fun checkIssuerTrust(cert: X509Certificate): Boolean {
        val trustedIssuers = setOf(
            "DigiCert", "GlobalSign", "VeriSign", "Symantec", "GeoTrust",
            "Comodo", "Thawte", "RapidSSL", "Let's Encrypt", "Amazon",
            "Google Trust Services", "Microsoft", "Apple"
        )
        
        val issuer = cert.issuerDN.name.uppercase()
        return trustedIssuers.any { issuer.contains(it.uppercase()) }
    }

    /**
     * Checks for weak signature algorithms
     */
    private fun isWeakSignatureAlgorithm(algorithm: String): Boolean {
        val weakAlgorithms = setOf(
            "MD5withRSA", "SHA1withRSA", "MD2withRSA", "MD4withRSA"
        )
        return weakAlgorithms.contains(algorithm)
    }

    /**
     * Checks for suspicious certificate attributes
     */
    private fun checkSuspiciousAttributes(cert: X509Certificate): List<String> {
        val warnings = mutableListOf<String>()
        
        // Check for very short validity periods (less than 30 days)
        val validityPeriod = cert.notAfter.time - cert.notBefore.time
        val validityDays = TimeUnit.MILLISECONDS.toDays(validityPeriod)
        if (validityDays < 30) {
            warnings.add("Certificate has unusually short validity period ($validityDays days)")
        }

        // Check for suspicious common names
        val subject = cert.subjectDN.name.lowercase()
        val suspiciousPatterns = listOf(
            "paypal", "amazon", "google", "microsoft", "apple", "facebook",
            "secure", "login", "account", "verify", "update"
        )
        
        suspiciousPatterns.forEach { pattern ->
            if (subject.contains(pattern) && !subject.contains("$pattern.com")) {
                warnings.add("Certificate contains suspicious keyword: $pattern")
            }
        }

        return warnings
    }

    private fun createFailureResult(message: String): SSLAnalysisResult {
        return SSLAnalysisResult(
            isSecure = false,
            certificateValid = false,
            issuerTrusted = false,
            domainMatches = false,
            expiryValid = false,
            riskScore = 100,
            warnings = listOf(message),
            certificateInfo = null
        )
    }
}