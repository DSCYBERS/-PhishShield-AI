package com.phishshieldai.android.ui.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.phishshieldai.android.R
import com.phishshieldai.android.data.model.ScanHistoryItem
import java.text.SimpleDateFormat
import java.util.*

class ScanHistoryAdapter(
    private val onItemClick: (ScanHistoryItem) -> Unit
) : ListAdapter<ScanHistoryItem, ScanHistoryAdapter.ScanHistoryViewHolder>(ScanHistoryDiffCallback()) {
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ScanHistoryViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_scan_history, parent, false)
        return ScanHistoryViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: ScanHistoryViewHolder, position: Int) {
        holder.bind(getItem(position))
    }
    
    inner class ScanHistoryViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val cardView: MaterialCardView = itemView.findViewById(R.id.scan_history_card)
        private val urlText: TextView = itemView.findViewById(R.id.url_text)
        private val threatLevelText: TextView = itemView.findViewById(R.id.threat_level_text)
        private val timestampText: TextView = itemView.findViewById(R.id.timestamp_text)
        private val statusText: TextView = itemView.findViewById(R.id.status_text)
        private val confidenceText: TextView = itemView.findViewById(R.id.confidence_text)
        private val threatTypesGroup: ChipGroup = itemView.findViewById(R.id.threat_types_group)
        private val detectionLayersGroup: ChipGroup = itemView.findViewById(R.id.detection_layers_group)
        
        private val dateFormat = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
        
        fun bind(item: ScanHistoryItem) {
            // Set URL (truncate if too long)
            urlText.text = if (item.url.length > 50) {
                item.url.take(50) + "..."
            } else {
                item.url
            }
            
            // Set threat level with appropriate color
            threatLevelText.text = item.threatLevel
            threatLevelText.setTextColor(getThreatLevelColor(item.threatLevel))
            
            // Set timestamp
            timestampText.text = dateFormat.format(Date(item.timestamp))
            
            // Set status
            statusText.text = if (item.blocked) "BLOCKED" else "ALLOWED"
            statusText.setTextColor(
                if (item.blocked) {
                    itemView.context.getColor(R.color.threat_high)
                } else {
                    itemView.context.getColor(R.color.success)
                }
            )
            
            // Set confidence
            confidenceText.text = "${String.format("%.1f", item.confidence)}%"
            
            // Set threat types
            threatTypesGroup.removeAllViews()
            item.threatTypes.forEach { threatType ->
                val chip = createChip(threatType, R.color.threat_medium)
                threatTypesGroup.addView(chip)
            }
            
            // Set detection layers
            detectionLayersGroup.removeAllViews()
            item.detectionLayers.forEach { layer ->
                val chip = createChip(layer, R.color.primary)
                detectionLayersGroup.addView(chip)
            }
            
            // Set card click listener
            cardView.setOnClickListener {
                onItemClick(item)
            }
            
            // Set card color based on threat level
            cardView.strokeColor = getThreatLevelColor(item.threatLevel)
        }
        
        private fun createChip(text: String, colorRes: Int): Chip {
            return Chip(itemView.context).apply {
                this.text = text
                isClickable = false
                isCheckable = false
                setChipBackgroundColorResource(R.color.surface_variant)
                setTextColor(itemView.context.getColor(colorRes))
                textSize = 10f
            }
        }
        
        private fun getThreatLevelColor(threatLevel: String): Int {
            return when (threatLevel.lowercase()) {
                "critical" -> itemView.context.getColor(R.color.threat_critical)
                "high" -> itemView.context.getColor(R.color.threat_high)
                "medium" -> itemView.context.getColor(R.color.threat_medium)
                "low" -> itemView.context.getColor(R.color.threat_low)
                else -> itemView.context.getColor(R.color.safe)
            }
        }
    }
    
    class ScanHistoryDiffCallback : DiffUtil.ItemCallback<ScanHistoryItem>() {
        override fun areItemsTheSame(oldItem: ScanHistoryItem, newItem: ScanHistoryItem): Boolean {
            return oldItem.id == newItem.id
        }
        
        override fun areContentsTheSame(oldItem: ScanHistoryItem, newItem: ScanHistoryItem): Boolean {
            return oldItem == newItem
        }
    }
}
