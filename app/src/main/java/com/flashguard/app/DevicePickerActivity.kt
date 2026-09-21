package com.flashguard.app

import android.app.Activity
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.flashguard.app.databinding.ActivityDevicePickerBinding
import com.flashguard.app.databinding.ItemDeviceBinding
import com.flashguard.engine.core.DeviceProfile
import com.flashguard.engine.device.DeviceDb

/** Searchable router database; picking one is what makes the compatibility verdict meaningful. */
class DevicePickerActivity : AppCompatActivity() {

    private lateinit var b: ActivityDevicePickerBinding
    private lateinit var adapter: DeviceAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityDevicePickerBinding.inflate(layoutInflater)
        setContentView(b.root)
        adapter = DeviceAdapter(DeviceDb.devices) { device ->
            LabHolder.device = device
            Prefs(this).lastDeviceId = device.id
            setResult(Activity.RESULT_OK)
            finish()
        }
        b.listDevices.layoutManager = LinearLayoutManager(this)
        b.listDevices.adapter = adapter
        b.inputSearch.doAfterTextChanged { text ->
            val results = filter(text?.toString().orEmpty())
            adapter.submit(results)
            b.textEmpty.visibility = if (results.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    private fun filter(query: String): List<DeviceProfile> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return DeviceDb.devices
        return DeviceDb.devices.filter { d ->
            d.brand.lowercase().contains(q) || d.model.lowercase().contains(q) ||
                d.revision.lowercase().contains(q) || d.soc.lowercase().contains(q) ||
                d.wifiChips.any { it.lowercase().contains(q) } || d.id.contains(q)
        }
    }

    private class DeviceAdapter(
        initial: List<DeviceProfile>,
        private val onClick: (DeviceProfile) -> Unit,
    ) : RecyclerView.Adapter<DeviceAdapter.VH>() {

        private val items = ArrayList<DeviceProfile>().apply { addAll(initial) }

        fun submit(list: List<DeviceProfile>) {
            items.clear()
            items.addAll(list)
            notifyDataSetChanged()
        }

        class VH(val item: ItemDeviceBinding) : RecyclerView.ViewHolder(item.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
            VH(ItemDeviceBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val d = items[position]
            holder.item.textTitle.text = d.display
            holder.item.textSpecs.text = "${d.soc}  •  ${d.cpuFamily.display}\n" +
                "${d.ramMb} MB RAM  •  ${d.flashMb} MB ${d.flashType}  •  ${d.bootloader}"
            holder.item.textExtra.text = buildString {
                if (d.wifiChips.isNotEmpty()) append("Wi-Fi: ${d.wifiChips.joinToString(", ")}\n")
                append("OpenWrt: ${d.openwrtSupport}")
                if (d.requiresSignedFirmware) append("  •  requires signed firmware")
            }
            holder.item.root.setOnClickListener { onClick(d) }
        }
    }
}
