package com.phishshieldai.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.phishshieldai.android.R
import com.phishshieldai.android.core.UrlInterceptor
import com.phishshieldai.android.core.PhishingDetectionEngine
import com.phishshieldai.android.ui.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import javax.inject.Inject

@AndroidEntryPoint
class PhishShieldVpnService : VpnService() {
    
    companion object {
        const val ACTION_START = "com.phishshieldai.android.START_VPN"
        const val ACTION_STOP = "com.phishshieldai.android.STOP_VPN"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "PhishShield_VPN"
        private const val TAG = "PhishShieldVpnService"
    }
    
    @Inject
    lateinit var urlInterceptor: UrlInterceptor
    
    @Inject
    lateinit var detectionEngine: PhishingDetectionEngine
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_START -> {
                startVpnService()
                START_STICKY
            }
            ACTION_STOP -> {
                stopVpnService()
                START_NOT_STICKY
            }
            else -> START_NOT_STICKY
        }
    }
    
    private fun startVpnService() {
        if (isRunning) return
        
        try {
            // Configure VPN interface
            val builder = Builder()
                .setSession("PhishShield VPN")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .setMtu(1500)
                .setBlocking(false)
            
            // Allow apps to bypass VPN if needed
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Could not disallow own app from VPN", e)
            }
            
            vpnInterface = builder.establish()
            
            if (vpnInterface != null) {
                isRunning = true
                startForeground(NOTIFICATION_ID, createNotification())
                
                // Start packet processing
                serviceScope.launch {
                    processPackets()
                }
                
                Log.i(TAG, "VPN service started successfully")
            } else {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN service", e)
            stopSelf()
        }
    }
    
    private fun stopVpnService() {
        isRunning = false
        
        try {
            vpnInterface?.close()
            vpnInterface = null
            
            serviceScope.cancel()
            stopForeground(true)
            stopSelf()
            
            Log.i(TAG, "VPN service stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping VPN service", e)
        }
    }
    
    private suspend fun processPackets() {
        val vpnInput = FileInputStream(vpnInterface?.fileDescriptor)
        val vpnOutput = FileOutputStream(vpnInterface?.fileDescriptor)
        
        val packet = ByteArray(32767)
        
        while (isRunning) {
            try {
                val length = vpnInput.read(packet)
                if (length > 0) {
                    // Process the packet
                    processPacket(ByteBuffer.wrap(packet, 0, length), vpnOutput)
                }
            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Error processing packet", e)
                }
                break
            }
        }
    }
    
    private suspend fun processPacket(packet: ByteBuffer, vpnOutput: FileOutputStream) {
        try {
            // Extract IP header
            val version = (packet.get(0).toInt() shr 4) and 0xF
            if (version != 4) return // Only handle IPv4 for now
            
            val protocol = packet.get(9).toInt() and 0xFF
            
            when (protocol) {
                17 -> processDnsPacket(packet, vpnOutput) // UDP (DNS)
                6 -> processTcpPacket(packet, vpnOutput)  // TCP (HTTP/HTTPS)
                else -> forwardPacket(packet, vpnOutput)   // Forward other protocols
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet", e)
            forwardPacket(packet, vpnOutput)
        }
    }
    
    private suspend fun processDnsPacket(packet: ByteBuffer, vpnOutput: FileOutputStream) {
        // Extract DNS query and check for malicious domains
        val dnsQuery = extractDnsQuery(packet)
        
        if (dnsQuery != null) {
            // Check if domain is malicious
            val scanResult = detectionEngine.quickDomainScan(dnsQuery)
            
            if (scanResult.isMalicious) {
                Log.i(TAG, "Blocked malicious domain: $dnsQuery")
                // Drop packet or return NXDOMAIN
                return
            }
        }
        
        // Forward legitimate DNS queries
        forwardPacket(packet, vpnOutput)
    }
    
    private suspend fun processTcpPacket(packet: ByteBuffer, vpnOutput: FileOutputStream) {
        // Extract HTTP/HTTPS requests and scan URLs
        val extractedUrl = extractHttpUrl(packet)
        
        if (extractedUrl != null) {
            // Perform full URL scan
            val scanResult = detectionEngine.scanUrl(extractedUrl)
            
            if (scanResult.isMalicious) {
                Log.i(TAG, "Blocked malicious URL: $extractedUrl")
                // Block the connection
                showPhishingWarning(extractedUrl, scanResult)
                return
            }
        }
        
        // Forward legitimate traffic
        forwardPacket(packet, vpnOutput)
    }
    
    private fun extractDnsQuery(packet: ByteBuffer): String? {
        try {
            // Skip IP header (20 bytes) and UDP header (8 bytes)
            packet.position(28)
            
            // DNS header is 12 bytes, skip it
            packet.position(packet.position() + 12)
            
            // Extract domain name from DNS query
            val domainBuilder = StringBuilder()
            var labelLength = packet.get().toInt() and 0xFF
            
            while (labelLength > 0 && packet.hasRemaining()) {
                // Read label
                val label = ByteArray(labelLength)
                packet.get(label)
                
                if (domainBuilder.isNotEmpty()) {
                    domainBuilder.append(".")
                }
                domainBuilder.append(String(label))
                
                // Get next label length
                if (packet.hasRemaining()) {
                    labelLength = packet.get().toInt() and 0xFF
                } else {
                    break
                }
            }
            
            val domain = domainBuilder.toString()
            Log.d(TAG, "Extracted DNS query: $domain")
            
            return if (domain.isNotEmpty()) domain else null
            
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract DNS query", e)
            return null
        }
    }
    
    private fun extractHttpUrl(packet: ByteBuffer): String? {
        try {
            // Skip IP header (typically 20 bytes)
            val ipHeaderLength = (packet.get(0).toInt() and 0x0F) * 4
            packet.position(ipHeaderLength)
            
            // Skip TCP header (typically 20 bytes, but check for options)
            val tcpHeaderLength = ((packet.get(packet.position() + 12).toInt() and 0xF0) shr 4) * 4
            packet.position(packet.position() + tcpHeaderLength)
            
            // Extract HTTP payload
            val remaining = packet.remaining()
            if (remaining < 10) return null // Too small for HTTP
            
            val httpPayload = ByteArray(remaining)
            packet.get(httpPayload)
            val httpString = String(httpPayload)
            
            // Look for HTTP request line
            val lines = httpString.split("\r\n")
            if (lines.isEmpty()) return null
            
            val requestLine = lines[0]
            if (!requestLine.startsWith("GET ") && !requestLine.startsWith("POST ")) {
                return null
            }
            
            // Extract Host header
            var host: String? = null
            for (line in lines) {
                if (line.lowercase().startsWith("host:")) {
                    host = line.substring(5).trim()
                    break
                }
            }
            
            if (host == null) return null
            
            // Extract path from request line
            val parts = requestLine.split(" ")
            if (parts.size < 2) return null
            
            val path = parts[1]
            val url = "http://$host$path"
            
            Log.d(TAG, "Extracted HTTP URL: $url")
            return url
            
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract HTTP URL", e)
            return null
        }
    }
    
    private fun forwardPacket(packet: ByteBuffer, vpnOutput: FileOutputStream) {
        try {
            vpnOutput.write(packet.array(), packet.position(), packet.remaining())
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding packet", e)
        }
    }
    
    private fun showPhishingWarning(url: String, scanResult: Any) {
        try {
            Log.w(TAG, "Phishing threat detected: $url")
            
            // Send broadcast for internal handling
            val intent = Intent("com.phishshieldai.android.PHISHING_DETECTED")
            intent.putExtra("url", url)
            intent.putExtra("timestamp", System.currentTimeMillis())
            sendBroadcast(intent)
            
            // Create high-priority notification for immediate user attention
            val notificationManager = getSystemService(NotificationManager::class.java)
            
            val warningIntent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("show_threat_warning", true)
                putExtra("threat_url", url)
            }
            
            val pendingIntent = PendingIntent.getActivity(
                this, 
                System.currentTimeMillis().toInt(),
                warningIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            
            val warningNotification = NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield_warning)
                .setContentTitle("🚨 Phishing Threat Blocked")
                .setContentText("Blocked access to: ${url.take(50)}${if (url.length > 50) "..." else ""}")
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("PhishShield AI has blocked access to a potentially malicious website:\n\n$url\n\nYour device is protected."))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .addAction(
                    R.drawable.ic_info,
                    "View Details",
                    pendingIntent
                )
                .setColor(0xFFFF4444.toInt()) // Red color for warning
                .build()
            
            notificationManager.notify(
                ("threat_" + System.currentTimeMillis()).hashCode(),
                warningNotification
            )
            
            // TODO: Consider implementing system overlay warning for immediate blocking
            // This would require SYSTEM_ALERT_WINDOW permission and careful UX design
            
        } catch (e: Exception) {
            Log.e(TAG, "Error showing phishing warning", e)
        }
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PhishShield VPN Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows when PhishShield VPN protection is active"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("PhishShield Protection Active")
            .setContentText("Monitoring and blocking malicious URLs")
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
    
    override fun onDestroy() {
        stopVpnService()
        super.onDestroy()
    }
}
