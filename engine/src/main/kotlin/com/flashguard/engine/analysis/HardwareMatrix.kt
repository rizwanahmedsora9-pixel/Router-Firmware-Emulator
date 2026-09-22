package com.flashguard.engine.analysis

import com.flashguard.engine.core.CpuFamily
import com.flashguard.engine.core.DeviceProfile
import com.flashguard.engine.core.EmulationResult
import com.flashguard.engine.core.FeatureVerdict
import com.flashguard.engine.core.FirmwareFacts
import com.flashguard.engine.core.HardwareFeature
import com.flashguard.engine.core.ImageFormat
import com.flashguard.engine.core.ImageIdentity
import com.flashguard.engine.core.RiskVerdict
import com.flashguard.engine.core.SocFamilies
import com.flashguard.engine.core.UnpackResult
import com.flashguard.engine.util.Hex
import com.flashguard.engine.util.Text

/**
 * The heart of "don't brick my router": matches what the image needs against what the user's router
 * actually has, and marks every mismatch - red means hardware-incompatible, i.e. do not flash.
 *
 * Every row carries the evidence it was derived from, because a verdict without evidence is a guess.
 */
object HardwareMatrix {

    fun evaluate(
        identity: ImageIdentity,
        facts: FirmwareFacts,
        unpack: UnpackResult,
        emulation: EmulationResult?,
        device: DeviceProfile,
    ): List<HardwareFeature> {
        val rows = ArrayList<HardwareFeature>()

        rows += archRow(identity, facts, device)
        rows += socRow(identity, facts, device)
        rows += flashSizeRow(identity, facts, device)
        rows += flashTypeRow(identity, facts, device)
        rows += bootloaderRow(identity, device)
        rows += signatureRow(identity, device, unpack)
        rows += wirelessRow(identity, facts, device, unpack)
        rows += usbRow(facts, device, unpack)
        rows += ramRow(facts, device)
        rows += deviceTreeRow(identity, device)
        rows += flashMethodRow(identity, unpack, device)
        rows += wholeFlashRow(identity, device)
        rows += bootEvidenceRow(emulation, unpack)
        rows += recoveryRow(device)
        rows += formatSupportRow(identity, unpack)
        return rows
    }

    // ------------------------------------------------------------------ individual rules

    private fun archRow(identity: ImageIdentity, facts: FirmwareFacts, device: DeviceProfile): HardwareFeature {
        val imageArch = facts.arch?.lowercase()
        val imageTarget = facts.target?.lowercase()
        val hints = (identity.archHints + listOfNotNull(imageArch, imageTarget)).joinToString(" ").lowercase()
        val deviceKeywords = device.cpuFamily.kernelArchKeywords

        val contradiction = contradictoryArch(hints, device.cpuFamily)
        return when {
            device.cpuFamily == CpuFamily.UNKNOWN -> HardwareFeature(
                "CPU architecture", "image: ${imageArch ?: imageTarget ?: "unknown"}", "device: unknown (custom profile)",
                FeatureVerdict.UNVERIFIED,
                "You did not tell the app the CPU family of this router, so architecture compatibility cannot be verified.",
                "Enter the CPU/SoC from the label (or pick a matching model) and re-run the check.",
            )
            contradiction != null -> HardwareFeature(
                "CPU architecture", "image targets $contradiction", "device is ${device.cpuFamily.display}",
                FeatureVerdict.INCOMPATIBLE,
                "This image was built for $contradiction, but your router's CPU is ${device.cpuFamily.display}. " +
                    "The kernel cannot execute on this SoC - flashing it produces a non-booting (bricked) router.",
                "Find the build for ${device.cpuFamily.display} (e.g. the correct OpenWrt target for your model).",
            )
            (device.cpuFamily == CpuFamily.MIPS_BE || device.cpuFamily == CpuFamily.MIPSEL) &&
                hints.contains("mips") &&
                !hints.contains("mipsel") && !hints.contains("brcm63") && !hints.contains("xburst") &&
                !hints.contains("ramips") && !hints.contains("mt7620") && !hints.contains("mt7621") &&
                !hints.contains("mt7628") && !hints.contains("mt76x8") && !hints.contains("rt305x") &&
                !hints.contains("ar71xx") && !hints.contains("ath79") && !hints.contains("mipseb") ->
                HardwareFeature(
                    "CPU architecture", "image: MIPS (endianness not declared)", "device: ${device.cpuFamily.display}",
                    FeatureVerdict.PARTIAL,
                    "The image identifies itself as MIPS, but neither its header nor its kernel banner states the " +
                        "endianness (uImage 'MIPS' covers both mips and mipsel). A kernel built for the wrong " +
                        "endianness will not boot.",
                    "Check the SoC on the label (Atheros/QCA and MediaTek MT76xx are big-endian; Broadcom BCM63xx " +
                        "is little-endian) and prefer a build that names your model explicitly.",
                )
            deviceKeywords.any { hints.contains(it) } -> HardwareFeature(
                "CPU architecture", "image: ${imageArch ?: imageTarget ?: hints.take(24)}", "device: ${device.cpuFamily.display}",
                FeatureVerdict.COMPATIBLE,
                "Architecture keywords in the image (${
                    (identity.archHints + listOfNotNull(imageArch, imageTarget)).take(4).joinToString(", ")
                }) match your router's CPU family.",
            )
            hints.isBlank() -> HardwareFeature(
                "CPU architecture", "image: not declared", "device: ${device.cpuFamily.display}",
                FeatureVerdict.UNVERIFIED,
                "The image does not declare its architecture (no OpenWrt metadata, no uImage/kernel banner found). " +
                    "If it does not match, the router will not boot.",
                "Compare the image name/version with the exact model+revision on the label before flashing.",
            )
            else -> HardwareFeature(
                "CPU architecture", "image: ${imageArch ?: imageTarget ?: hints.take(24)}", "device: ${device.cpuFamily.display}",
                FeatureVerdict.PARTIAL,
                "The image mentions architectures (${identity.archHints.take(3).joinToString(", ")}) that do not clearly match " +
                    "${device.cpuFamily.display}, but no direct contradiction was found.",
                "Prefer a build that names your model explicitly.",
            )
        }
    }

    private fun contradictoryArch(hints: String, family: CpuFamily): String? {
        if (hints.isBlank()) return null
        val isMips = hints.contains("mips") || hints.contains("ar7") || hints.contains("ath7") || hints.contains("ramips") || hints.contains("mt76")
        // Little-endian MIPS router lineage: explicit "mipsel", Broadcom BCM63xx, Xburst.
        // NOTE: "ramips", "mt7620/mt7621/mt7628", "mt76x8" are NOT little-endian markers -
        // the MediaTek MT76xx and Ralink SoCs (the ramips OpenWrt target) are BIG-endian.
        val isMipsel = hints.contains("mipsel") || hints.contains("brcm63") || hints.contains("xburst")
        // Bare "mips" is ENDIAN-AMBIGUOUS: the uImage arch code 5 ("MIPS") and kernel
        // banners ("... mips") cover both big- and little-endian builds. Only explicit
        // markers may be treated as big-endian, otherwise a vendor's own mipsel
        // kernel (e.g. a BCM63xx board) would be falsely flagged as a brick.
        val isMipsBe = (hints.contains("ar71xx") || hints.contains("ath79") ||
            hints.contains("mipseb") || hints.contains("mips_be") || hints.contains("big-endian") ||
            hints.contains("ramips") || hints.contains("mt7620") || hints.contains("mt7621") ||
            hints.contains("mt7628") || hints.contains("mt76x8") || hints.contains("rt305x")) && isMips
        val isArm = hints.contains("armv7") || hints.contains("armhf") || hints.contains("cortex-a7") || hints.contains("cortex-a9") || hints.contains("arm32")
        val isArm64 = hints.contains("aarch64") || hints.contains("arm64") || hints.contains("cortex-a5")
        val isX86 = hints.contains("x86") || hints.contains("i386") || hints.contains("amd64")

        return when (family) {
            CpuFamily.MIPS_BE -> when {
                isMipsel -> "MIPS little-endian (mipsel/ramips)"
                isArm || isArm64 -> "ARM"
                isX86 -> "x86"
                else -> null
            }
            CpuFamily.MIPSEL -> when {
                isMipsBe && !isMipsel -> "MIPS big-endian (ar71xx/ath79/ramips/MT76xx)"
                isArm || isArm64 -> "ARM"
                isX86 -> "x86"
                else -> null
            }
            CpuFamily.ARM_LE -> when {
                isMips -> "MIPS"
                isArm64 -> "ARM64 (aarch64)"
                isX86 -> "x86"
                else -> null
            }
            CpuFamily.AARCH64 -> when {
                isMips -> "MIPS"
                isArm && !isArm64 -> "32-bit ARM (armv7)"
                isX86 -> "x86"
                else -> null
            }
            CpuFamily.X86 -> when {
                isMips || isArm || isArm64 -> "embedded SoC (MIPS/ARM)"
                else -> null
            }
            CpuFamily.RISCV -> when {
                isMips || isArm || isArm64 -> "MIPS/ARM"
                else -> null
            }
            CpuFamily.UNKNOWN -> null
        }
    }

    /**
     * Chip-level check: which SoC family was the image built for vs which SoC is in the router.
     *
     * This catches what the CPU-architecture row structurally cannot: images for a *different
     * SoC of the same architecture* (MT7620 vs MT7628, QCA9531 vs MT7621, ...). Those are the
     * "same model, different hardware revision" bricks - e.g. a TL-WR720N v1 (MT7620AT) image
     * on a v2 (MT7628AN) board.
     *
     * Honesty rule: it only claims a verdict when BOTH sides name a specific SoC family. A
     * generic/custom device profile ("MediaTek MT7620", "unknown") or an image without any SoC
     * string yields UNVERIFIED, never a guessed mismatch.
     */
    private fun socRow(identity: ImageIdentity, facts: FirmwareFacts, device: DeviceProfile): HardwareFeature {
        val imageText = (identity.archHints + identity.evidence +
            listOfNotNull(facts.target, facts.arch, facts.distro, facts.deviceModelHint) +
            facts.socHints).joinToString(" ")
        val imageSoc = SocFamilies.fromText(imageText)
        val deviceSoc = SocFamilies.fromText(device.soc)
        return when {
            imageSoc == null && deviceSoc == null -> HardwareFeature(
                "SoC family (chip match)", "image: not declared", "device: not specific enough",
                FeatureVerdict.UNVERIFIED,
                "Neither the image nor the device profile names a specific SoC, so the chip-level match " +
                    "cannot be checked.",
                "Images are normally only safe for the exact model + hardware revision - confirm the label.",
            )
            imageSoc == null -> HardwareFeature(
                "SoC family (chip match)", "image: not declared", "device: ${deviceSoc!!.name}",
                FeatureVerdict.UNVERIFIED,
                "The image does not declare which SoC it was built for (no device tree, board string or " +
                    "SoC marker found), so the chip-level match against ${deviceSoc.name} could not be verified.",
                "Compare the image name/version with the exact model + revision on the label before flashing.",
            )
            deviceSoc == null -> HardwareFeature(
                "SoC family (chip match)", "image targets ${imageSoc!!.name}", "device: not specific enough",
                FeatureVerdict.UNVERIFIED,
                "The image targets ${imageSoc.name}, but the selected device profile does not name a specific " +
                    "SoC to compare against.",
                "Pick the exact model (or the matching generic SoC profile) to enable the chip-level check.",
            )
            imageSoc.name == deviceSoc.name -> HardwareFeature(
                "SoC family (chip match)", "image: ${imageSoc.name}", "device: ${deviceSoc.name}",
                FeatureVerdict.COMPATIBLE,
                "The image's SoC family (${imageSoc.name}) matches the router's SoC - the strongest hardware " +
                    "match available in a static check.",
            )
            else -> HardwareFeature(
                "SoC family (chip match)", "image targets ${imageSoc.name}", "device has ${deviceSoc.name}",
                FeatureVerdict.INCOMPATIBLE,
                "This image was built for a ${imageSoc.name} board, but your router has a ${deviceSoc.name}. " +
                    "Even when both are the same CPU architecture, the kernel will not find its hardware on the " +
                    "other SoC and the router will not boot - this is how 'same model, different hardware " +
                    "revision' flashes brick a router.",
                "Use the build that names your exact model + revision (e.g. the matching TP-Link hardware " +
                    "version of the WR720N family).",
            )
        }
    }

    private fun flashSizeRow(identity: ImageIdentity, facts: FirmwareFacts, device: DeviceProfile): HardwareFeature {
        val needed = facts.requiredFlashMb
        val deviceMb = device.flashMb
        val fileMb = identity.totalSize / (1024.0 * 1024.0)
        val sizeLabel = if (identity.primary == ImageFormat.TPLINK_IMG0) "image file" else "image rootfs"
        val fileText = "$sizeLabel ${needed?.let { String.format(java.util.Locale.US, "%.1f MB", it) } ?: "unknown"} " +
            "(file ${Hex.humanBytes(identity.totalSize)})"
        return when {
            // Evidence, not absence of evidence: a file that is bigger than the whole flash chip
            // cannot be written, no matter what is inside it.
            deviceMb > 0 && fileMb > deviceMb * 1.02 -> HardwareFeature(
                "Flash size", "$fileText - larger than the flash chip",
                "device has $deviceMb MB",
                FeatureVerdict.INCOMPATIBLE,
                "The file is ${Hex.humanBytes(identity.totalSize)}, which is larger than your router's entire ${deviceMb} MB flash. " +
                    "The write would fail part-way through and leave an incomplete (bricked) image - or the bootloader would " +
                    "reject it as too big.",
                "Double-check you downloaded the image for this model/revision (or the correct 8 MB variant) and that the download is not corrupt.",
            )
            deviceMb == 0 || needed == null -> HardwareFeature(
                "Flash size", fileText,
                "device: ${if (deviceMb > 0) "$deviceMb MB" else "unknown"}",
                FeatureVerdict.UNVERIFIED,
                "Could not compare sizes: " + if (deviceMb == 0) "the device profile has no flash size." else "the image rootfs size could not be measured (nothing inside the file could be unpacked).",
                "Compare this file's size with the vendor's download for your exact model + revision, and with the free space your router reports.",
            )
            needed > deviceMb -> HardwareFeature(
                "Flash size", "image needs ~${String.format(java.util.Locale.US, "%.1f MB", needed)} (uncompressed rootfs)",
                "device has ${deviceMb} MB",
                FeatureVerdict.INCOMPATIBLE,
                "The uncompressed rootfs alone is larger than your router's whole flash. The write will fail part-way " +
                    "through and leave an incomplete (bricked) image.",
                "Use a trimmed build for ${deviceMb} MB devices, or a model with more flash.",
            )
            needed > deviceMb * 0.9 -> HardwareFeature(
                "Flash size", "image needs ~${String.format(java.util.Locale.US, "%.1f MB", needed)}", "device has ${deviceMb} MB",
                FeatureVerdict.PARTIAL,
                "The image uses more than 90% of the flash. It may just fit, but there will be no room for JFFS2/overlay " +
                    "and later upgrades will fail.",
                "Keep an eye on free space; consider a smaller build (e.g. without LuCI extras).",
            )
            else -> HardwareFeature(
                "Flash size", "image needs ~${String.format(java.util.Locale.US, "%.1f MB", needed)}",
                "device has ${deviceMb} MB",
                FeatureVerdict.COMPATIBLE,
                "The extracted rootfs fits comfortably in your router's flash with room for the overlay.",
            )
        }
    }

    private fun flashTypeRow(identity: ImageIdentity, facts: FirmwareFacts, device: DeviceProfile): HardwareFeature {
        val imageIsNand = identity.primary == ImageFormat.UBI || identity.primary == ImageFormat.UBIFS ||
            identity.layers.flatMap { it.flattenTree() }.any { it.format == ImageFormat.UBI || it.format == ImageFormat.UBIFS } ||
            facts.target?.contains("nand", true) == true
        val imageIsNor = !imageIsNand && (identity.primary == ImageFormat.SQUASHFS || identity.primary == ImageFormat.TRX ||
            identity.primary == ImageFormat.NETGEAR_CHK || identity.primary == ImageFormat.TPLINK_BIN || identity.primary == ImageFormat.TPLINK_IMG0)
        val deviceNand = device.flashType.equals("NAND", true)
        val deviceNor = device.flashType.equals("NOR", true)
        return when {
            device.flashType == "UNKNOWN" -> HardwareFeature(
                "Flash type (NOR vs NAND)", if (imageIsNand) "image is a NAND/UBI image" else if (imageIsNor) "image looks like a NOR/raw image" else "unknown",
                "device: unknown",
                FeatureVerdict.UNVERIFIED,
                "NOR and NAND flashes need completely different images. Flashing the wrong kind is a classic brick.",
                "Check whether your router has a NAND or NOR flash (the model's wiki page states it).",
            )
            imageIsNand && deviceNor -> HardwareFeature(
                "Flash type (NOR vs NAND)", "image is a NAND/UBI image", "device has ${device.flashType} flash",
                FeatureVerdict.INCOMPATIBLE,
                "This image is built for NAND (UBI volumes). A NOR-flash router cannot boot it - the bootloader will not " +
                    "find a kernel.",
                "Use the NOR build for this model.",
            )
            imageIsNor && deviceNand -> HardwareFeature(
                "Flash type (NOR vs NAND)", "image is not a UBI image", "device has NAND flash",
                FeatureVerdict.PARTIAL,
                "This image carries no UBI/UBIFS container. Many NAND boards (e.g. Netgear MT7621 models) boot a plain " +
                    "squashfs from NAND, in which case this is normal; on boards whose bootloader requires UBI it will not " +
                    "fit. The container alone cannot decide.",
                "If this is the vendor's official file for your exact model, it matches your board's layout. Otherwise " +
                    "prefer the factory/NAND image for this model.",
            )
            device.flashType == "SD" -> HardwareFeature(
                "Flash type (NOR vs NAND)", "image type: ${identity.primary.label}", "device boots from ${device.flashType}",
                FeatureVerdict.COMPATIBLE,
                "This device boots from removable media, so a bad image cannot brick it - the safest possible test bench.",
            )
            else -> HardwareFeature(
                "Flash type (NOR vs NAND)", "image type: ${identity.primary.label}", "device has ${device.flashType} flash",
                FeatureVerdict.COMPATIBLE,
                "The image's flash layout is consistent with this device's flash type.",
            )
        }
    }

    private fun bootloaderRow(identity: ImageIdentity, device: DeviceProfile): HardwareFeature {
        val format = identity.primary
        val expectsCfe = device.bootloader.contains("CFE", true)
        val expectsUboot = device.bootloader.contains("U-Boot", true)
        val expectsVxWorks = device.bootloader.contains("VxWorks", true)
        val imageLooksCfe = format == ImageFormat.TRX || format == ImageFormat.NETGEAR_CHK || format == ImageFormat.DLINK_SHR
        // Only the PRIMARY container decides the boot path: vendor containers (Netgear CHK,
        // ASUS .zip, TP-Link .bin) routinely carry a uImage-format *kernel* inside, which is
        // normal and does not make the image "U-Boot style".
        val imageLooksUboot = format == ImageFormat.UBOOT_LEGACY || format == ImageFormat.UBOOT_FIT
        return when {
            expectsVxWorks && format == ImageFormat.TPLINK_IMG0 -> HardwareFeature(
                "Bootloader format", "image is TP-Link IMG0/VxWorks", "device uses ${device.bootloader}",
                FeatureVerdict.COMPATIBLE,
                "The image wrapper matches the stock TP-Link/VxWorks upgrade format used by this device.",
            )
            expectsCfe && imageLooksUboot -> HardwareFeature(
                "Bootloader format", "image is a U-Boot style image", "device uses CFE",
                FeatureVerdict.INCOMPATIBLE,
                "Your router's bootloader is CFE (Broadcom), which only understands its own image format " +
                    "(TRX/CHK). A U-Boot image will be rejected or written as garbage.",
                "Use the CFE/TRX formatted build for this device.",
            )
            expectsUboot && imageLooksCfe -> HardwareFeature(
                "Bootloader format", "image is a CFE/vendor container (${format.label})", "device uses U-Boot",
                FeatureVerdict.PARTIAL,
                "This is a vendor container built for a CFE-style bootloader. U-Boot will normally refuse it unless the " +
                    "image is the vendor's own file for this exact model.",
                "Only flash this if it is the vendor's own file for your exact model+revision.",
            )
            imageLooksUboot -> HardwareFeature(
                "Bootloader format", "image is a U-Boot style image", "device uses ${device.bootloader}",
                FeatureVerdict.COMPATIBLE,
                "Image format matches the device bootloader family.",
            )
            else -> HardwareFeature(
                "Bootloader format", "image: ${format.label}", "device uses ${device.bootloader}",
                FeatureVerdict.UNVERIFIED,
                "The image does not carry a recognisable bootloader container, so the boot path could not be verified.",
            )
        }
    }

    private fun signatureRow(identity: ImageIdentity, device: DeviceProfile, unpack: UnpackResult): HardwareFeature {
        val vendorSigned = identity.primary == ImageFormat.TPLINK_SIGNED ||
            identity.evidence.any { it.contains("encrypted or signed", true) } ||
            identity.evidence.any { it.contains("high entropy", true) }
        return when {
            device.requiresSignedFirmware && !vendorSigned -> HardwareFeature(
                "Vendor signature", "image is not vendor-signed", "device requires signed firmware",
                FeatureVerdict.INCOMPATIBLE,
                "${device.display} checks the firmware signature in the bootloader. Unsigned images are rejected or, " +
                    "worse, half-written before the check fails.",
                "Use the vendor's own signed firmware, or a documented unlock procedure for this model.",
            )
            vendorSigned -> HardwareFeature(
                "Vendor signature", "image appears signed/encrypted", "device requires signed firmware: ${device.requiresSignedFirmware}",
                FeatureVerdict.PARTIAL,
                "The payload is signed or encrypted by the vendor, so the engine could only inspect the wrapper, not the " +
                    "rootfs. Nothing inside could be verified or emulated.",
                "Treat this image as opaque: only flash it if it came from the vendor for this exact model.",
            )
            !unpack.inspected -> HardwareFeature(
                "Vendor signature", "unknown - the image could not be unpacked", "device requires signed firmware: ${device.requiresSignedFirmware}",
                FeatureVerdict.UNVERIFIED,
                "Nothing inside the file could be read, so the engine cannot tell whether it is signed, and it cannot tell " +
                    "whether it is even an image for this device.",
                "Confirm where the file came from and that it names your exact model + revision before flashing it.",
            )
            else -> HardwareFeature(
                "Vendor signature", "image is not signed", "device does not require signatures",
                FeatureVerdict.COMPATIBLE,
                "No signature gate detected, so the bootloader will accept a custom image.",
            )
        }
    }

    private fun wirelessRow(identity: ImageIdentity, facts: FirmwareFacts, device: DeviceProfile, unpack: UnpackResult): HardwareFeature {
        val imageDrivers = facts.wirelessDrivers
        val deviceChips = device.wifiChips
        // HONESTY GATE: "the image ships no wireless drivers" is only evidence when the image was
        // actually read. On an opaque payload (raw/vendor-encrypted blob, UBI/UBIFS rootfs) the
        // missing module list is *absence of evidence* - calling the radio dead there is a false
        // "do not flash" on what may be the vendor's own stock image.
        if (!unpack.inspected) {
            return HardwareFeature(
                "Wi-Fi hardware",
                "unknown - this image could not be unpacked" + if (imageDrivers.isEmpty()) "" else " (only ${imageDrivers.size} driver(s) visible)",
                "device has ${deviceChips.ifEmpty { listOf("unknown wireless chipset") }.joinToString(", ")}",
                FeatureVerdict.UNVERIFIED,
                "The engine could not read inside this file (${unpack.opaqueReason() ?: "no readable rootfs"}), so it cannot " +
                    "tell whether it ships drivers for ${deviceChips.firstOrNull() ?: "this router's radio"}. That is a limit of a " +
                    "static phone-side check - it is NOT a hardware mismatch.",
                "Unpack the image on a PC (binwalk / unsquashfs) to list its wireless modules, or use a build this app can read " +
                    "(squashfs, tar.gz, uImage) and re-run the check.",
            )
        }
        if (identity.primary == ImageFormat.TPLINK_IMG0 && imageDrivers.isEmpty()) {
            return HardwareFeature(
                "Wi-Fi hardware", "VxWorks stock image (wireless drivers are monolithic, not .ko modules)",
                "device has ${deviceChips.ifEmpty { listOf("unknown wireless chipset") }.joinToString(", ")}",
                FeatureVerdict.UNVERIFIED,
                "This is a VxWorks/IMG0 stock firmware, so Wi-Fi support is built into the OS image rather than exposed as Linux kernel modules. The module-list check is not applicable.",
                "Only use it if it is the vendor file for the exact model/revision on the label.",
            )
        }
        if (deviceChips.isEmpty()) {
            return HardwareFeature(
                "Wi-Fi hardware", "image drivers: ${imageDrivers.take(5).joinToString(", ").ifEmpty { "none found" }}",
                "device: unknown wireless chipset", FeatureVerdict.UNVERIFIED,
                "The device profile does not list a wireless chipset, so driver match cannot be checked.",
                "If Wi-Fi must work, confirm the router's radio chip (label / wiki) and compare with the image's drivers.",
            )
        }
        val deviceTokens = deviceChips.joinToString(" ").lowercase()
            .split(Regex("[^a-z0-9]+")).filter { it.length >= 4 }.toSet()
        val imageTargetsDevice = imageDrivers.any { drv ->
            val d = drv.lowercase()
            deviceTokens.any { tok -> d.contains(tok) } ||
                (d.contains("mt76") && deviceTokens.any { it.startsWith("mt7") }) ||
                (d.contains("ath") && deviceTokens.any { it.startsWith("qca") || it.startsWith("ar9") }) ||
                // Broadcom: proprietary "wl" (stock ASUS/D-Link firmware), open "b43", in-kernel "brcm*"
                ((d == "wl" || d.contains("b43") || d.contains("brcm")) &&
                    deviceTokens.any { it.startsWith("bcm") || it.startsWith("broadcom") }) ||
                (d.contains("rtl") && deviceTokens.contains("rtl"))
        }
        return when {
            imageDrivers.isEmpty() -> HardwareFeature(
                "Wi-Fi hardware", "image ships no wireless drivers", "device has ${deviceChips.joinToString(", ")}",
                FeatureVerdict.INCOMPATIBLE,
                "The image contains no wireless kernel modules at all, so this router's radio would stay dead.",
                "Pick an image that includes the wireless drivers for ${deviceChips.first()}.",
            )
            imageTargetsDevice -> HardwareFeature(
                "Wi-Fi hardware", "image drivers match this chipset", "device has ${deviceChips.joinToString(", ")}",
                FeatureVerdict.COMPATIBLE,
                "Drivers/modules for this wireless hardware are present in the image.",
            )
            else -> HardwareFeature(
                "Wi-Fi hardware", "image drivers: ${imageDrivers.take(4).joinToString(", ")}",
                "device has ${deviceChips.joinToString(", ")}",
                FeatureVerdict.INCOMPATIBLE,
                "The image ships drivers for other wireless chipsets, not for ${deviceChips.first()}. The router would " +
                    "boot but its Wi-Fi would never come up (and on some models the radios block the boot entirely).",
                "Use the build for ${deviceChips.first()}, or add the correct driver package.",
            )
        }
    }

    private fun usbRow(facts: FirmwareFacts, device: DeviceProfile, unpack: UnpackResult): HardwareFeature = when {
        !unpack.inspected -> HardwareFeature(
            "USB / storage", "unknown - this image could not be unpacked", if (device.usb) "device has USB ports" else "device has no USB",
            FeatureVerdict.UNVERIFIED,
            "The image's contents could not be read, so USB support cannot be checked either way. This does not affect the " +
                "verdict, but it is one more thing that is unverified rather than confirmed.",
        )
        !facts.usbSupported -> HardwareFeature(
            "USB / storage", "image has no USB support", if (device.usb) "device has USB ports" else "device has no USB",
            FeatureVerdict.COMPATIBLE,
            "Nothing in the image requires USB, so this does not affect boot.",
        )
        !device.usb -> HardwareFeature(
            "USB / storage", "image enables USB support", "device has no USB port",
            FeatureVerdict.PARTIAL,
            "The image supports USB but your router has no USB port. This is harmless for booting - the USB features " +
            "simply will not exist.",
        )
        else -> HardwareFeature(
            "USB / storage", "image enables USB support", "device has USB",
            FeatureVerdict.COMPATIBLE,
            "USB support in the image matches the hardware.",
        )
    }

    private fun ramRow(facts: FirmwareFacts, device: DeviceProfile): HardwareFeature {
        val targetRam = when {
            facts.target?.contains("mt7621") == true -> 64
            facts.target?.contains("mt76x8") == true -> 32
            facts.target?.contains("ar9331") == true -> 16
            facts.target?.contains("ath79") == true -> 32
            facts.target?.contains("ar71xx") == true -> 16
            facts.target?.contains("ramips") == true -> 32
            facts.target?.contains("ipq") == true -> 128
            facts.target?.contains("bcm53xx") == true -> 128
            facts.target?.contains("filogic") == true -> 128
            facts.target?.contains("mvebu") == true -> 128
            else -> null
        }
        return when {
            device.ramMb == 0 -> HardwareFeature(
                "RAM", "image target: ${facts.target ?: "unknown"}", "device RAM unknown", FeatureVerdict.UNVERIFIED,
                "Device RAM is unknown, so memory requirements cannot be compared.",
            )
            targetRam == null -> HardwareFeature(
                "RAM", "image target: ${facts.target ?: "unknown"}", "device has ${device.ramMb} MB",
                FeatureVerdict.UNVERIFIED,
                "The image does not declare a RAM requirement. Typical builds for this class of device need 32-128 MB.",
            )
            device.ramMb >= targetRam -> HardwareFeature(
                "RAM", "typical need for ${facts.target} ~${targetRam} MB", "device has ${device.ramMb} MB",
                FeatureVerdict.COMPATIBLE,
                "RAM is sufficient for this target's usual image size.",
            )
            else -> HardwareFeature(
                "RAM", "typical need for ${facts.target} ~${targetRam} MB", "device has ${device.ramMb} MB",
                FeatureVerdict.PARTIAL,
                "This is on the low side for ${facts.target}. The router may boot but fail under load or during " +
                    "sysupgrade (upgrades hold the image in RAM).",
                "Prefer a minimal build and free RAM before flashing.",
            )
        }
    }

    private fun deviceTreeRow(identity: ImageIdentity, device: DeviceProfile): HardwareFeature {
        val modelHints = identity.evidence.filter { it.startsWith("FDT compatible") || it.startsWith("FDT model") || it.startsWith("Kernel machine") }
        if (modelHints.isEmpty()) {
            val imageModel = identity.model
            val modelToken = device.model.lowercase().replace("-", "")
            val imageToken = imageModel?.lowercase()?.replace("-", "") ?: ""
            if (imageModel != null && modelToken.isNotBlank() && imageToken.contains(modelToken)) {
                return HardwareFeature(
                    "Device tree / board name", "image model: $imageModel", "selected: ${device.display}",
                    FeatureVerdict.COMPATIBLE,
                    "No Linux device tree is present, but the firmware identity/filename names the selected router model.",
                )
            }
            return HardwareFeature(
                "Device tree / board name", "no device-tree model found", "selected: ${device.display}",
                FeatureVerdict.UNVERIFIED,
                "The image did not expose a device-tree model string, so you need to confirm the target device from the " +
                    "image name/version.",
            )
        }
        val text = modelHints.joinToString(" ").lowercase()
        val modelToken = device.model.lowercase().replace("-", "")
        val match = modelToken.isNotBlank() && text.replace("-", "").contains(modelToken)
        return if (match) {
            HardwareFeature(
                "Device tree / board name", Text.truncate(modelHints.first(), 90), "selected: ${device.display}",
                FeatureVerdict.COMPATIBLE,
                "The image's board/device-tree name mentions your router model.",
            )
        } else {
            HardwareFeature(
                "Device tree / board name", Text.truncate(modelHints.first(), 90), "selected: ${device.display}",
                FeatureVerdict.PARTIAL,
                "The image's board name does not mention ${device.model}. It may still be a generic build for this SoC, " +
                    "but port assignments (LAN/WAN/Wi-Fi LEDs) can differ.",
                "Prefer the image whose file name names your exact model and revision.",
            )
        }
    }

    private fun flashMethodRow(identity: ImageIdentity, unpack: UnpackResult, device: DeviceProfile): HardwareFeature {
        val sysupgrade = identity.primary == ImageFormat.OPENWRT_SYSUPGRADE || unpack.vfs.exists("/CONTROL") ||
            unpack.vfs.exists("/sysupgrade-")
        val hasWebUi = unpack.vfs.findWebRoots().isNotEmpty()
        return when {
            identity.primary == ImageFormat.TPLINK_IMG0 -> HardwareFeature(
                "Install method", "TP-Link stock IMG0/VxWorks upgrade image", "device: ${device.display}",
                FeatureVerdict.COMPATIBLE,
                "Use the stock TP-Link web upgrade/recovery path for this exact hardware revision; this is not an OpenWrt sysupgrade package.",
            )
            sysupgrade -> HardwareFeature(
                "Install method", "image is a sysupgrade package", "device currently running: unknown firmware",
                FeatureVerdict.PARTIAL,
                "A sysupgrade image is meant to be flashed *from an already-running OpenWrt/DD-WRT* (or from the " +
                    "vendor's upgrade page for vendor images). Flashing it over stock firmware usually fails.",
                "If your router still runs stock firmware, you need the factory image (or the vendor's own file) first.",
            )
            hasWebUi && device.openwrtSupport.startsWith("yes") -> HardwareFeature(
                "Install method", "vendor/standard image", "device: ${device.display}",
                FeatureVerdict.COMPATIBLE,
                "Flash through your router's own upgrade page, or OpenWrt's sysupgrade if it already runs OpenWrt.",
            )
            else -> HardwareFeature(
                "Install method", "image: ${identity.primary.label}", "device: ${device.display}",
                FeatureVerdict.UNVERIFIED,
                "The correct install path depends on what is currently running on the router (stock vs OpenWrt).",
                "Stock firmware -> use the vendor upgrade page with a vendor/factory image. Already OpenWrt -> sysupgrade.",
            )
        }
    }

    private fun wholeFlashRow(identity: ImageIdentity, device: DeviceProfile): HardwareFeature {
        if (identity.primary != ImageFormat.RAW) {
            return HardwareFeature(
                "Image scope", "partition/firmware image (${identity.primary.label})", "recommended: partition image",
                FeatureVerdict.COMPATIBLE,
                "This image contains a firmware payload rather than a raw whole-flash dump.",
            )
        }
        // A raw blob tells us almost nothing about its own scope - only its size is a clue, and the
        // size of the device's flash is the one thing we do know. Previously any raw file under
        // 2 MB was declared a "partition/firmware image", which is not something the bytes support.
        val fileMb = identity.totalSize / (1024.0 * 1024.0)
        val looksLikeFullFlash = device.flashMb > 0 && fileMb >= device.flashMb * 0.95 && fileMb <= device.flashMb * 1.05
        return if (looksLikeFullFlash) {
            HardwareFeature(
                "Image scope", "whole-flash size (${String.format(java.util.Locale.US, "%.1f", fileMb)} MB, no recognised container)",
                "device flash is ${device.flashMb} MB",
                FeatureVerdict.PARTIAL,
                "This blob is the exact size of your router's whole ${device.flashMb} MB flash and carries no recognised " +
                    "firmware container, so it is very likely a *complete flash dump* (bootloader + partitions + radio " +
                    "calibration data). Writing it erases the bootloader - that is exactly how routers become unrecoverable bricks.",
                "Only restore a full dump to the exact device it came from, using that bootloader's recovery path. For an " +
                    "upgrade, use a partition image instead.",
            )
        } else {
            HardwareFeature(
                "Image scope", "raw blob, ${String.format(java.util.Locale.US, "%.1f", fileMb)} MB, no recognised container",
                "device flash is ${if (device.flashMb > 0) "${device.flashMb} MB" else "unknown"}",
                FeatureVerdict.UNVERIFIED,
                "The file contains no recognisable firmware container, so the engine cannot tell whether it is a partition " +
                    "image, a whole-flash dump or not a firmware image at all (a checksum cannot tell you either).",
                "Verify what the file is before treating it as an upgrade image: compare its name and size with the vendor's " +
                    "download page for your exact model + revision, or unpack it on a PC.",
            )
        }
    }

    private fun bootEvidenceRow(emulation: EmulationResult?, unpack: UnpackResult? = null): HardwareFeature {
        if (emulation == null) {
            return HardwareFeature(
                "Static boot test", "emulation not run", "no boot evidence",
                FeatureVerdict.UNVERIFIED,
                "The image was analysed but not emulated, so there is no evidence about whether it reaches init.",
            )
        }
        val reachedInit = emulation.reachedInit()
        val reachedWeb = emulation.reachedWebUi()
        // "Could not extract a rootfs" (UBI/UBIFS/JFFS2/EXT mounts, vendor-encrypted blobs)
        // is NOT the same as "init failed": the first is a verification limit, not a hardware
        // mismatch. Flagging it red would tell users "do not flash" their own stock images.
        val staticallyUnreadable = unpack != null && unpack.vfs.fileCount <= 5
        return when {
            reachedWeb -> HardwareFeature(
                "Static boot test", "reached init + web UI in the sandbox", "${emulation.commandsRun} shell steps in ${emulation.elapsedMs} ms",
                FeatureVerdict.COMPATIBLE,
                "The image's own init scripts ran to the point of bringing up a web UI${emulation.loginPage?.let { " (login page: ${Text.baseName(it)})" } ?: ""}. " +
                    "In the sandbox it boots cleanly.",
            )
            reachedInit -> HardwareFeature(
                "Static boot test", "reached init in the sandbox", "${emulation.commandsRun} shell steps",
                FeatureVerdict.PARTIAL,
                "Init scripts executed, but the web UI never came up in emulation. On the real device this usually still " +
                    "boots, but the admin page may be missing or broken.",
            )
            staticallyUnreadable -> HardwareFeature(
                "Static boot test", "rootfs could not be read in the sandbox", "${emulation.commandsRun} shell steps",
                FeatureVerdict.UNVERIFIED,
                "This image's rootfs is inside a container the phone cannot mount statically (UBI/UBIFS, JFFS2, ext4, or a " +
                    "vendor-encrypted blob), so no boot evidence could be gathered. That is a limitation of the on-device " +
                    "check, not evidence that the image is incompatible.",
                "Verify on a test unit, or use a build with a squashfs/gzip rootfs that this app can read.",
            )
            else -> HardwareFeature(
                "Static boot test", "boot chain did not complete in the sandbox", "${emulation.commandsRun} shell steps",
                FeatureVerdict.INCOMPATIBLE,
                "The sandbox could not drive this image to a running system (no init scripts executed or the rootfs could " +
                    "not be extracted). That is a strong warning sign.",
                "Check the emulation log for the first failing stage before flashing anything.",
            )
        }
    }

    private fun recoveryRow(device: DeviceProfile): HardwareFeature = HardwareFeature(
        "Recovery path (if it goes wrong)", device.recovery, "device: ${device.display}",
        if (device.recovery.contains("unknown", true)) FeatureVerdict.UNVERIFIED else FeatureVerdict.COMPATIBLE,
        if (device.recovery.contains("unknown", true))
            "No documented recovery method is known for this profile - write down the model's own recovery procedure before flashing."
        else device.recovery,
    )

    private fun formatSupportRow(identity: ImageIdentity, unpack: UnpackResult): HardwareFeature {
        val unsupported = unpack.unsupported
        // "coverage: 100% of this image" must never appear for an image nothing could be read from -
        // that row is the first thing a user checks when deciding how much to trust the report.
        if (!unpack.inspected) {
            val reason = unpack.opaqueReason() ?: "no container, filesystem, archive or compression stream was recognised"
            return HardwareFeature(
                "Static analysis coverage", "nothing could be read inside this file (${identity.primary.label})",
                "engine coverage: header bytes + size only",
                FeatureVerdict.PARTIAL,
                "The engine could not unpack anything from this image: $reason. Every check below is therefore based on the " +
                    "file's size, its first bytes and its entropy - not on its contents - so unmatchable rows are reported as " +
                    "'needs verification' instead of being guessed at.",
                "Unpack it on a PC (binwalk / unsquashfs) or use a build with a container this app can read (squashfs, tar.gz, " +
                    "uImage, TRX), then re-run the check for content-level evidence.",
            )
        }
        if (identity.primary == ImageFormat.TPLINK_IMG0) {
            return HardwareFeature(
                "Static analysis coverage", "TP-Link IMG0 parsed; VxWorks web UI store extracted",
                "engine coverage: IMG0 headers + stock web UI + size checks",
                FeatureVerdict.COMPATIBLE,
                "The official VxWorks container and its Wind River web store were recognised and decoded. Native VxWorks binaries are not executed by the static emulator, but the upgrade wrapper and admin UI are no longer opaque.",
            )
        }
        return if (unsupported.isEmpty()) {
            HardwareFeature(
                "Static analysis coverage", "full: container + rootfs were readable", "engine coverage: 100% of this image",
                FeatureVerdict.COMPATIBLE,
                "Every layer of this image could be unpacked and inspected on-device.",
            )
        } else {
            HardwareFeature(
                "Static analysis coverage", Text.truncate(unsupported.first(), 110), "engine could not fully inspect this image",
                FeatureVerdict.PARTIAL,
                "Part of this image could not be inspected on a phone (${unsupported.size} limitation(s)), so the report is " +
                    "based on partial evidence.",
                "Treat unknown parts as unverified; a full check needs a PC-based unpacking tool.",
            )
        }
    }

    // ------------------------------------------------------------------ scoring

    fun score(rows: List<HardwareFeature>): Int {
        var score = 0
        for (r in rows) {
            score += when (r.verdict) {
                FeatureVerdict.INCOMPATIBLE -> 45
                FeatureVerdict.PARTIAL -> 8
                // Unverified rows describe missing *evidence*, not risk. Weighting them heavily made
                // an image nothing could be read from score 100/100 - which reads as "this will brick
                // your router" when the truth is "we could not look inside".
                FeatureVerdict.UNVERIFIED -> 6
                FeatureVerdict.COMPATIBLE -> 0
                FeatureVerdict.MISSING -> 0
            }
        }
        // Without a single verified mismatch the score must stay in the "we don't know" band.
        if (rows.none { it.verdict.isRed }) score = minOf(score, 55)
        return minOf(score, 100)
    }

    /**
     * @param imageInspected false when nothing inside the image could be unpacked. That state is
     *   reported as [RiskVerdict.CANNOT_VERIFY] (no evidence either way), never as a "hardware
     *   mismatch" - a proven red row still wins, because that one *is* evidence.
     */
    fun verdict(rows: List<HardwareFeature>, imageInspected: Boolean = true): RiskVerdict {
        val red = rows.count { it.verdict.isRed }
        val amber = rows.count { it.verdict == FeatureVerdict.PARTIAL || it.verdict == FeatureVerdict.UNVERIFIED }
        return when {
            red > 0 -> RiskVerdict.DO_NOT_FLASH
            !imageInspected && amber > 0 -> RiskVerdict.CANNOT_VERIFY
            amber > 0 -> RiskVerdict.NEEDS_MANUAL_REVIEW
            else -> RiskVerdict.SAFE_TO_FLASH_AFTER_BACKUP
        }
    }

    fun nextSteps(
        rows: List<HardwareFeature>,
        device: DeviceProfile,
        emulation: EmulationResult?,
        unpack: UnpackResult? = null,
    ): List<String> {
        val steps = ArrayList<String>()
        val red = rows.filter { it.verdict.isRed }
        if (red.isNotEmpty()) {
            steps.add("Do NOT flash this image: ${red.size} hardware mismatch(es) - ${red.joinToString("; ") { it.feature }}.")
            red.forEach { r -> r.mitigation?.let { steps.add("${r.feature}: $it") } }
            return steps
        }
        if (unpack != null && !unpack.inspected) {
            steps.add(
                "Do not flash this file on this evidence: the engine could not read anything inside it, so none of the checks " +
                    "in this report are evidence about your router either way (see the findings for the exact reason)."
            )
            steps.add(
                "Confirm the file itself: download the firmware for ${device.display} again from the vendor's own support page " +
                    "(or firmware-selector.openwrt.org for OpenWrt) and compare the file size and SHA-256 with this one."
            )
            steps.add("If it is the right file, open it on a PC (binwalk, unsquashfs, 7-Zip) and check it is not truncated, encrypted or vendor-wrapped.")
            steps.add("Use a build this app can read end-to-end (squashfs / tar.gz / uImage / TRX) if you want content-level evidence before flashing.")
            steps.add("If you still decide to install it: take a full flash backup first, and keep the recovery path ready - ${device.recovery}")
            return steps
        }
        steps.add("Take a full backup first: SSH into the router and dump every partition (or use the vendor's backup function).")
        steps.add("Confirm the hardware revision on the label matches '${device.display}' before downloading anything else.")
        if (emulation?.reachedWebUi() == true) {
            steps.add("The image boots to a web UI in emulation - try the login page in the emulator tab to see the UI you will get.")
        } else {
            steps.add("Emulation did not reach a web UI: consider testing the image on a spare/SD-boot device, or on a device whose recovery is known.")
        }
        steps.add("Keep the recovery path ready: ${device.recovery}")
        steps.add("Flash over a wired connection with stable power (never Wi-Fi, never during a storm).")
        steps.add("After flashing, wait a full 5 minutes without power-cycling, then test the login page.")
        return steps
    }
}
