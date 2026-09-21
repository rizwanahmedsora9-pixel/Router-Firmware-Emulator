package com.flashguard.app

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.flashguard.app.databinding.ActivityMatrixBinding
import com.flashguard.app.databinding.ItemMatrixBinding
import com.flashguard.engine.core.FeatureVerdict
import com.flashguard.engine.core.HardwareFeature

/**
 * The compatibility matrix. Red rows are hardware-incompatible - flashing those parts of an image
 * is what bricks routers, so they are also listed first.
 */
class MatrixActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val b = ActivityMatrixBinding.inflate(layoutInflater)
        setContentView(b.root)
        val session = LabHolder.session ?: run {
            finish()
            return
        }
        val report = session.report
        val red = report.redFlags().size
        b.matrixVerdict.setBackgroundResource(
            when {
                red > 0 -> R.drawable.bg_verdict_red
                report.riskScore > 15 -> R.drawable.bg_verdict_amber
                else -> R.drawable.bg_verdict_green
            }
        )
        b.textMatrixVerdict.text = "${report.verdict.display}  (risk ${report.riskScore}/100)"
        b.textMatrixSub.text = buildString {
            append("$red red flag(s) of ${report.features.size} checks for ${report.device.display}.\n")
            append(if (red > 0) {
                "A red row means the image needs hardware this router does not have: the kernel would not boot, or a subsystem (Wi-Fi/NAND) would stay dead."
            } else {
                "No hard incompatibility found. Amber rows are things the static test cannot prove - read the notes, keep a backup, and have a recovery path ready."
            })
        }

        val sorted = report.features.sortedWith(
            compareByDescending<HardwareFeature> { it.verdict.isRed }
                .thenByDescending { it.verdict == FeatureVerdict.PARTIAL || it.verdict == FeatureVerdict.UNVERIFIED }
                .thenBy { it.feature }
        )
        b.listMatrix.layoutManager = LinearLayoutManager(this)
        b.listMatrix.adapter = MatrixAdapter(sorted)
    }

    private class MatrixAdapter(private val rows: List<HardwareFeature>) : RecyclerView.Adapter<MatrixAdapter.VH>() {

        class VH(val item: ItemMatrixBinding) : RecyclerView.ViewHolder(item.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
            VH(ItemMatrixBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun getItemCount(): Int = rows.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val row = rows[position]
            val ctx = holder.item.root.context
            holder.item.textFeature.text = row.feature
            holder.item.textValues.text = "image: ${row.imageWants}\nyour router: ${row.deviceHas}"
            holder.item.textWhy.text = row.why
            val (chipText, chipBg, chipColor) = when {
                row.verdict.isRed -> Triple("RED - INCOMPATIBLE", R.drawable.bg_chip_red, R.color.bad_red)
                row.verdict == FeatureVerdict.COMPATIBLE -> Triple("OK", R.drawable.bg_chip_green, R.color.ok_green)
                row.verdict == FeatureVerdict.PARTIAL -> Triple("CAUTION", R.drawable.bg_chip_amber, R.color.warn_amber)
                else -> Triple("VERIFY", R.drawable.bg_chip_amber, R.color.warn_amber)
            }
            holder.item.textVerdictChip.text = chipText
            holder.item.textVerdictChip.setBackgroundResource(chipBg)
            holder.item.textFeature.setTextColor(ContextCompat.getColor(ctx, chipColor))
            row.mitigation?.let {
                holder.item.textMitigation.visibility = android.view.View.VISIBLE
                holder.item.textMitigation.text = "→ $it"
            } ?: run { holder.item.textMitigation.visibility = android.view.View.GONE }
        }
    }
}
