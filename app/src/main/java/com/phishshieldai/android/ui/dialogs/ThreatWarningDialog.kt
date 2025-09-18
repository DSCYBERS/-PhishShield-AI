package com.phishshieldai.android.ui.dialogs

import android.app.Dialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.DialogFragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.phishshieldai.android.R
import com.phishshieldai.android.databinding.DialogThreatWarningBinding
import com.phishshieldai.android.data.model.ThreatAnalysis
import com.phishshieldai.android.data.model.ThreatLevel
import com.phishshieldai.android.data.model.ThreatSource
import com.phishshieldai.android.ui.adapters.ThreatSourcesAdapter
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class ThreatWarningDialog : DialogFragment() {
    
    private var _binding: DialogThreatWarningBinding? = null
    private val binding get() = _binding!!
    
    private lateinit var threatAnalysis: ThreatAnalysis
    private var onActionSelected: ((ThreatWarningAction) -> Unit)? = null
    
    enum class ThreatWarningAction {
        BLOCK_AND_CONTINUE,
        ALLOW_ONCE,
        WHITELIST_DOMAIN,
        REPORT_FALSE_POSITIVE,
        VIEW_DETAILS,
        SHARE_THREAT
    }
    
    companion object {
        fun newInstance(
            threatAnalysis: ThreatAnalysis,
            onActionSelected: (ThreatWarningAction) -> Unit
        ): ThreatWarningDialog {
            return ThreatWarningDialog().apply {
                this.threatAnalysis = threatAnalysis
                this.onActionSelected = onActionSelected
            }
        }
    }
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = DialogThreatWarningBinding.inflate(inflater, container, false)
        return binding.root
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupUI()
        setupClickListeners()
    }
    
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = super.onCreateDialog(savedInstanceState)
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        return dialog
    }
    
    private fun setupUI() {
        binding.apply {
            // Set threat level styling
            when (threatAnalysis.threatLevel) {
                ThreatLevel.CRITICAL -> {
                    threatLevelIndicator.setCardBackgroundColor(
                        ContextCompat.getColor(requireContext(), R.color.threat_critical)
                    )
                    threatLevelText.text = "CRITICAL THREAT"
                    threatLevelText.setTextColor(ContextCompat.getColor(requireContext(), R.color.white))
                    threatIcon.setImageResource(R.drawable.ic_threat_critical)
                    threatIcon.imageTintList = ContextCompat.getColorStateList(requireContext(), R.color.white)
                }
                ThreatLevel.HIGH -> {
                    threatLevelIndicator.setCardBackgroundColor(
                        ContextCompat.getColor(requireContext(), R.color.threat_high)
                    )
                    threatLevelText.text = "HIGH THREAT"
                    threatLevelText.setTextColor(ContextCompat.getColor(requireContext(), R.color.white))
                    threatIcon.setImageResource(R.drawable.ic_threat_high)
                    threatIcon.imageTintList = ContextCompat.getColorStateList(requireContext(), R.color.white)
                }
                ThreatLevel.MEDIUM -> {
                    threatLevelIndicator.setCardBackgroundColor(
                        ContextCompat.getColor(requireContext(), R.color.threat_medium)
                    )
                    threatLevelText.text = "MEDIUM THREAT"
                    threatLevelText.setTextColor(ContextCompat.getColor(requireContext(), R.color.white))
                    threatIcon.setImageResource(R.drawable.ic_threat_medium)
                    threatIcon.imageTintList = ContextCompat.getColorStateList(requireContext(), R.color.white)
                }
                else -> {
                    threatLevelIndicator.setCardBackgroundColor(
                        ContextCompat.getColor(requireContext(), R.color.threat_medium)
                    )
                    threatLevelText.text = "SUSPICIOUS"
                    threatLevelText.setTextColor(ContextCompat.getColor(requireContext(), R.color.white))
                    threatIcon.setImageResource(R.drawable.ic_threat_medium)
                    threatIcon.imageTintList = ContextCompat.getColorStateList(requireContext(), R.color.white)
                }
            }
            
            // Set URL and domain
            threatUrl.text = threatAnalysis.url
            threatDomain.text = "Domain: ${threatAnalysis.domain}"
            
            // Set threat description
            threatDescription.text = getThreatDescription()
            
            // Set confidence score
            confidenceScore.text = "${(threatAnalysis.confidence * 100).toInt()}%"
            confidenceProgressBar.progress = (threatAnalysis.confidence * 100).toInt()
            
            // Set detection time
            detectionTime.text = "Detected: ${threatAnalysis.detectionTime}"
            
            // Setup threat categories
            setupThreatCategories()
            
            // Setup threat sources
            setupThreatSources()
            
            // Setup analysis layers
            setupAnalysisLayers()
            
            // Setup technical details (initially hidden)
            technicalDetailsContainer.visibility = View.GONE
            setupTechnicalDetails()
        }
    }
    
    private fun setupClickListeners() {
        binding.apply {
            // Primary actions
            btnBlockThreat.setOnClickListener {
                onActionSelected?.invoke(ThreatWarningAction.BLOCK_AND_CONTINUE)
                dismiss()
            }
            
            btnAllowOnce.setOnClickListener {
                showAllowOnceConfirmation()
            }
            
            // Secondary actions
            btnWhitelistDomain.setOnClickListener {
                showWhitelistConfirmation()
            }
            
            btnReportFalsePositive.setOnClickListener {
                onActionSelected?.invoke(ThreatWarningAction.REPORT_FALSE_POSITIVE)
                showReportConfirmation()
            }
            
            // Additional actions
            btnShareThreat.setOnClickListener {
                shareThreatInfo()
            }
            
            btnViewDetails.setOnClickListener {
                onActionSelected?.invoke(ThreatWarningAction.VIEW_DETAILS)
                // Keep dialog open for details view
            }
            
            // Technical details toggle
            btnShowTechnicalDetails.setOnClickListener {
                toggleTechnicalDetails()
            }
            
            // Close button
            btnClose.setOnClickListener {
                dismiss()
            }
        }
    }
    
    private fun setupThreatCategories() {
        binding.threatCategoriesContainer.removeAllViews()
        
        threatAnalysis.categories.forEach { category ->
            val chip = Chip(requireContext()).apply {
                text = category.uppercase()
                isCloseIconVisible = false
                isClickable = false
                setChipBackgroundColorResource(R.color.threat_category_bg)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_category_text))
            }
            binding.threatCategoriesContainer.addView(chip)
        }
    }
    
    private fun setupThreatSources() {
        val adapter = ThreatSourcesAdapter(threatAnalysis.threatSources)
        binding.threatSourcesList.apply {
            this.adapter = adapter
            layoutManager = LinearLayoutManager(requireContext())
            isNestedScrollingEnabled = false
        }
    }
    
    private fun setupAnalysisLayers() {
        binding.analysisLayersContainer.removeAllViews()
        
        threatAnalysis.analysisLayers.forEach { layer ->
            val chip = Chip(requireContext()).apply {
                text = layer
                isCloseIconVisible = false
                isClickable = false
                setChipBackgroundColorResource(R.color.analysis_layer_bg)
                setTextColor(ContextCompat.getColor(requireContext(), R.color.analysis_layer_text))
                setChipIconResource(getLayerIcon(layer))
            }
            binding.analysisLayersContainer.addView(chip)
        }
    }
    
    private fun setupTechnicalDetails() {
        binding.apply {
            // ML Model Details
            mlModelName.text = threatAnalysis.mlModelDetails?.modelName ?: "PhishShield AI v1.0"
            mlModelVersion.text = threatAnalysis.mlModelDetails?.version ?: "1.0.0"
            mlConfidenceScore.text = "${(threatAnalysis.mlModelDetails?.confidence ?: 0.0 * 100).toInt()}%"
            
            // Feature Analysis
            setupFeatureAnalysis()
            
            // Network Analysis
            if (threatAnalysis.networkAnalysis != null) {
                networkAnalysisContainer.visibility = View.VISIBLE
                ipAddress.text = threatAnalysis.networkAnalysis.ipAddress
                serverLocation.text = threatAnalysis.networkAnalysis.serverLocation
                sslCertificate.text = if (threatAnalysis.networkAnalysis.hasValidSSL) "Valid" else "Invalid/Missing"
            } else {
                networkAnalysisContainer.visibility = View.GONE
            }
            
            // Threat Intelligence Details
            setupThreatIntelligenceDetails()
        }
    }
    
    private fun setupFeatureAnalysis() {
        binding.featureAnalysisContainer.removeAllViews()
        
        threatAnalysis.featureAnalysis?.topFeatures?.forEach { feature ->
            val featureView = LayoutInflater.from(requireContext())
                .inflate(R.layout.item_feature_analysis, binding.featureAnalysisContainer, false)
            
            featureView.findViewById<TextView>(R.id.feature_name).text = feature.name
            featureView.findViewById<TextView>(R.id.feature_value).text = feature.value.toString()
            featureView.findViewById<ProgressBar>(R.id.feature_importance).progress = 
                (feature.importance * 100).toInt()
            
            binding.featureAnalysisContainer.addView(featureView)
        }
    }
    
    private fun setupThreatIntelligenceDetails() {
        binding.apply {
            if (threatAnalysis.threatIntelligence != null) {
                threatIntelContainer.visibility = View.VISIBLE
                
                val threatIntel = threatAnalysis.threatIntelligence
                threatIntelSources.text = "${threatIntel.sourcesCount} sources"
                threatIntelLastUpdate.text = "Updated: ${threatIntel.lastUpdate}"
                threatIntelReputation.text = threatIntel.reputation
                
                // Setup threat intel sources list
                threatIntelSourcesList.removeAllViews()
                threatIntel.detailedSources.forEach { source ->
                    val sourceView = LayoutInflater.from(requireContext())
                        .inflate(R.layout.item_threat_intel_source, threatIntelSourcesList, false)
                    
                    sourceView.findViewById<TextView>(R.id.source_name).text = source.name
                    sourceView.findViewById<TextView>(R.id.source_verdict).text = source.verdict
                    sourceView.findViewById<TextView>(R.id.source_confidence).text = 
                        "${(source.confidence * 100).toInt()}%"
                    
                    val statusIndicator = sourceView.findViewById<View>(R.id.source_status_indicator)
                    statusIndicator.setBackgroundColor(
                        if (source.isMalicious) 
                            ContextCompat.getColor(requireContext(), R.color.threat_high)
                        else 
                            ContextCompat.getColor(requireContext(), R.color.safe)
                    )
                    
                    threatIntelSourcesList.addView(sourceView)
                }
            } else {
                threatIntelContainer.visibility = View.GONE
            }
        }
    }
    
    private fun toggleTechnicalDetails() {
        binding.apply {
            if (technicalDetailsContainer.visibility == View.GONE) {
                technicalDetailsContainer.visibility = View.VISIBLE
                btnShowTechnicalDetails.text = "Hide Technical Details"
                btnShowTechnicalDetails.setIconResource(R.drawable.ic_expand_less)
            } else {
                technicalDetailsContainer.visibility = View.GONE
                btnShowTechnicalDetails.text = "Show Technical Details"
                btnShowTechnicalDetails.setIconResource(R.drawable.ic_expand_more)
            }
        }
    }
    
    private fun showAllowOnceConfirmation() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Allow URL Once?")
            .setMessage("This will allow access to the potentially dangerous URL for this session only. The URL will be blocked again in the future.\n\nProceed with caution.")
            .setPositiveButton("Allow Once") { _, _ ->
                onActionSelected?.invoke(ThreatWarningAction.ALLOW_ONCE)
                dismiss()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun showWhitelistConfirmation() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Whitelist Domain?")
            .setMessage("This will permanently allow all URLs from the domain '${threatAnalysis.domain}'. This action cannot be easily undone.\n\nOnly whitelist domains you completely trust.")
            .setPositiveButton("Whitelist") { _, _ ->
                onActionSelected?.invoke(ThreatWarningAction.WHITELIST_DOMAIN)
                dismiss()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun showReportConfirmation() {
        Toast.makeText(
            requireContext(),
            "False positive report sent. Thank you for helping improve PhishShield AI!",
            Toast.LENGTH_LONG
        ).show()
    }
    
    private fun shareThreatInfo() {
        val shareText = """
            PhishShield AI Threat Detection Report
            
            URL: ${threatAnalysis.url}
            Threat Level: ${threatAnalysis.threatLevel}
            Confidence: ${(threatAnalysis.confidence * 100).toInt()}%
            Categories: ${threatAnalysis.categories.joinToString(", ")}
            
            Detected by PhishShield AI - Advanced Phishing Protection
        """.trimIndent()
        
        val shareIntent = Intent().apply {
            action = Intent.ACTION_SEND
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, shareText)
            putExtra(Intent.EXTRA_SUBJECT, "PhishShield AI Threat Report")
        }
        
        startActivity(Intent.createChooser(shareIntent, "Share threat information"))
    }
    
    private fun getThreatDescription(): String {
        return when (threatAnalysis.threatLevel) {
            ThreatLevel.CRITICAL -> "This URL has been identified as an active phishing site with high confidence. Accessing it may compromise your personal information, passwords, or financial data."
            ThreatLevel.HIGH -> "This URL shows strong indicators of being a phishing or malicious site. It may attempt to steal your personal information or install malware."
            ThreatLevel.MEDIUM -> "This URL has suspicious characteristics that suggest it may be used for phishing or other malicious activities. Proceed with extreme caution."
            else -> "This URL has been flagged for suspicious behavior. While it may be legitimate, exercise caution when providing any personal information."
        }
    }
    
    private fun getLayerIcon(layer: String): Int {
        return when (layer.lowercase()) {
            "lexical" -> R.drawable.ic_text_analysis
            "reputation" -> R.drawable.ic_reputation
            "content" -> R.drawable.ic_content_analysis
            "ml" -> R.drawable.ic_ml_model
            "sandbox" -> R.drawable.ic_sandbox
            "networkgraph" -> R.drawable.ic_network_analysis
            "threatintelligence" -> R.drawable.ic_threat_intelligence
            else -> R.drawable.ic_analysis_layer
        }
    }
    
    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
