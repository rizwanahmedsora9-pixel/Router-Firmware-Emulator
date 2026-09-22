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
import com.flashguard.engine.core.UnpackResult
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
        rows += flashSizeRow(facts, unpack, device)
        rows += flashTypeRow(identity, facts, device)
        rows += bootloaderRow(identity, device)
        rows += signatureRow(identity, device)
        rows += wirelessRow(facts, device)
        rows += usbRow(facts, device)
        rows += ramRow(facts, device)
        rows += deviceTreeRow(identity, device)
        rows += flashMethodRow(identity, unpack, device)
        rows += wholeFlashRow(identity)
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
                !hints.contains("mipsel") && !hints.contains("ramips") &&
                !hints.contains("ar71xx") && !hints.contains("ath79") && !hints.contains("mipseb") ->
                HardwareFeature(
                    "CPU architecture", "image: MIPS (endianness not declared)", "device: ${device.cpuFamily.display}",
                    FeatureVerdict.PARTIAL,
                    "The image identifies itself as MIPS, but neither its header nor its kernel banner states the " +
                        "endianness (uImage 'MIPS' covers both mips and mipsel). A kernel built for the wrong " +
                        "endianness will not boot.",
                    "Check the SoC on the label (Atheros/QCA = big-endian, MediaTek/Ralink = little-endian) and " +
                        "prefer a build that names your model explicitly.",
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
        val isMipsel = hints.contains("mipsel") || hints.contains("ramips") || hints.contains("mt7620") || hints.contains("mt7621") || hints.contains("mt76x8")
        // Bare "mips" is ENDIAN-AMBIGUOUS: the uImage arch code 5 ("MIPS") and kernel
        // banners ("... mips") cover both big- and little-endian builds. Only explicit
        // BE markers may be treated as big-endian, otherwise a vendor's own mipsel
        // kernel (e.g. Netgear MT7621) would be falsely flagged as a brick.
        val isMipsBe = (hints.contains("ar71xx") || hints.contains("ath79") ||
            hints.contains("mipseb") || hints.contains("mips_be") || hints.contains("big-endian")) && isMips
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
                isMipsBe && !isMipsel -> "MIPS big-endian (ar71xx/ath79)"
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

    private fun flashSizeRow(facts: FirmwareFacts, unpack: UnpackResult, device: DeviceProfile): HardwareFeature {
        val needed = facts.requiredFlashMb
        val deviceMb = device.flashMb
        return when {
            deviceMb == 0 || needed == null -> HardwareFeature(
                "Flash size", "image rootfs ${needed?.let { String.format(java.util.Locale.US, "%.1f MB", it) } ?: "unknown"}",
                "device: ${if (deviceMb > 0) "$deviceMb MB" else "unknown"}",
                FeatureVerdict.UNVERIFIED,
                "Could not compare sizes: " + if (deviceMb == 0) "the device profile has no flash size." else "the image rootfs size could not be measured.",
                "Cheapest safe check: compare the firmware size shown here with the free space your router reports.",
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
                "Flash size", "image needs ~${String.format(java.util.Locale.US, "%.1f MB", needed)} (${unpack.importedFiles} files)",
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
            identity.primary == ImageFormat.NETGEAR_CHK || identity.primary == ImageFormat.TPLINK_BIN)
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
        val imageLooksCfe = format == ImageFormat.TRX || format == ImageFormat.NETGEAR_CHK || format == ImageFormat.DLINK_SHR
        // Only the PRIMARY container decides the boot path: vendor containers (Netgear CHK,
        // ASUS .zip, TP-Link .bin) routinely carry a uImage-format *kernel* inside, which is
        // normal and does not make the image "U-Boot style".
        val imageLooksUboot = format == ImageFormat.UBOOT_LEGACY || format == ImageFormat.UBOOT_FIT
        return when {
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

    private fun signatureRow(identity: ImageIdentity, device: DeviceProfile): HardwareFeature {
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
            else -> HardwareFeature(
                "Vendor signature", "image is not signed", "device does not require signatures",
                FeatureVerdict.COMPATIBLE,
                "No signature gate detected, so the bootloader will accept a custom image.",
            )
        }
    }

    private fun wirelessRow(facts: FirmwareFacts, device: DeviceProfile): HardwareFeature {
        val imageDrivers = facts.wirelessDrivers
        val deviceChips = device.wifiChips
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

    private fun usbRow(facts: FirmwareFacts, device: DeviceProfile): HardwareFeature = when {
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
            facts.target?.contains("ath79") == true -> 32
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

    private fun wholeFlashRow(identity: ImageIdentity): HardwareFeature {
        val looksWholeFlash = identity.primary == ImageFormat.RAW && identity.totalSize > 2L * 1024 * 1024
        return if (looksWholeFlash) {
            HardwareFeature(
                "Image scope", "whole-flash dump (${identity.totalSize / (1024 * 1024)} MB, no recognised container)",
                "you are flashing a full flash image",
                FeatureVerdict.PARTIAL,
                "This looks like a *complete flash dump* (bootloader + partitions). Writing it will erase the bootloader " +
                    "and calibration data of your router - that is exactly how routers become unrecoverable bricks.",
                "Prefer a partition image, or understand that you are restoring a full backup to the *same* device it came from.",
            )
        } else {
            HardwareFeature(
                "Image scope", "partition/firmware image (${identity.primary.label})", "recommended: partition image",
                FeatureVerdict.COMPATIBLE,
                "This image contains a firmware payload rather than a raw whole-flash dump.",
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
                FeatureVerdict.UNVERIFIED -> 12
                FeatureVerdict.COMPATIBLE -> 0
                FeatureVerdict.MISSING -> 0
            }
        }
        return minOf(score, 100)
    }

    fun verdict(rows: List<HardwareFeature>): RiskVerdict {
        val red = rows.count { it.verdict.isRed }
        val amber = rows.count { it.verdict == FeatureVerdict.PARTIAL || it.verdict == FeatureVerdict.UNVERIFIED }
        return when {
            red > 0 -> RiskVerdict.DO_NOT_FLASH
            amber > 4 -> RiskVerdict.NEEDS_MANUAL_REVIEW
            amber > 0 -> RiskVerdict.NEEDS_MANUAL_REVIEW
            else -> RiskVerdict.SAFE_TO_FLASH_AFTER_BACKUP
        }
    }

    fun nextSteps(rows: List<HardwareFeature>, device: DeviceProfile, emulation: EmulationResult?): List<String> {
        val steps = ArrayList<String>()
        val red = rows.filter { it.verdict.isRed }
        if (red.isNotEmpty()) {
            steps.add("Do NOT flash this image: ${red.size} hardware mismatch(es) - ${red.joinToString("; ") { it.feature }}.")
            red.forEach { r -> r.mitigation?.let { steps.add("${r.feature}: $it") } }
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
