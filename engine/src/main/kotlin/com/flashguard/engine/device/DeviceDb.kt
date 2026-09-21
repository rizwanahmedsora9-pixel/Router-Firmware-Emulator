package com.flashguard.engine.device

import com.flashguard.engine.core.CpuFamily
import com.flashguard.engine.core.DeviceProfile

/**
 * Built-in hardware profiles for the routers people actually flash.
 *
 * These are decision-support facts, not gospel: revisions of the *same* model frequently ship a
 * different SoC, which is why the app always shows the revision and asks the user to confirm the
 * label on the bottom of the device. Anything not listed can be entered manually (custom profile).
 */
object DeviceDb {

    val devices: List<DeviceProfile> = listOf(
        // ---------------------------------------------------------------- TP-Link
        DeviceProfile(
            id = "tplink-tl-wr841n-v13", brand = "TP-Link", model = "TL-WR841N", revision = "v13/v14",
            soc = "Qualcomm QCA9531", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 550,
            ramMb = 32, flashMb = 8, flashLayout = "8 MB NOR (u-boot + kernel + rootfs)", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("QCA9531 (ath9k, 2.4 GHz)"),
            extraFeatures = listOf("4x 100M LAN", "1x 100M WAN"), ethernetPorts = 5, gigabit = false,
            requiresSignedFirmware = false, openwrtSupport = "yes (ath79)",
            stockLogin = "admin / admin", recovery = "TFTP recovery: rename image to wr841nv14_tp_recovery.bin, serve at 192.168.0.66, power on while holding reset",
            notes = "v13/v14 use QCA9531; v8-v12 use AR9341 - do not mix images.",
        ),
        DeviceProfile(
            id = "tplink-tl-wr841n-v8", brand = "TP-Link", model = "TL-WR841N", revision = "v8/v9",
            soc = "Qualcomm/Atheros AR9341", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 535,
            ramMb = 32, flashMb = 4, flashLayout = "4 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("AR9341 (ath9k, 2.4 GHz)"),
            extraFeatures = listOf("4x 100M LAN"), ethernetPorts = 5, gigabit = false,
            openwrtSupport = "yes (ath79)", stockLogin = "admin / admin",
            recovery = "TFTP recovery at 192.168.0.66",
            notes = "4 MB flash: only very small OpenWrt images fit.",
        ),
        DeviceProfile(
            id = "tplink-archer-c6-v2", brand = "TP-Link", model = "Archer C6", revision = "v2",
            soc = "MediaTek MT7621A", cpuFamily = CpuFamily.MIPSEL, cpuCores = 2, cpuMhz = 880,
            ramMb = 128, flashMb = 16, flashLayout = "16 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("MediaTek MT7603E (2.4 GHz)", "MediaTek MT7613 (5 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet"), usb = false, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (ramips/mt7621)", stockLogin = "admin / (set on first boot)",
            recovery = "TFTP recovery at 192.168.0.1 (hold reset while powering on)",
        ),
        DeviceProfile(
            id = "tplink-archer-c7-v2", brand = "TP-Link", model = "Archer C7", revision = "v2",
            soc = "Qualcomm QCA9558", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 720,
            ramMb = 128, flashMb = 16, flashLayout = "16 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("QCA9880 (ath10k, 5 GHz)", "AR9580 (ath9k, 2.4 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet", "USB 2.0"), usb = true, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (ath79)", stockLogin = "admin / admin",
            recovery = "TFTP recovery at 192.168.0.1",
        ),
        DeviceProfile(
            id = "tplink-archer-c20-v4", brand = "TP-Link", model = "Archer C20", revision = "v4",
            soc = "MediaTek MT7628", cpuFamily = CpuFamily.MIPSEL, cpuCores = 1, cpuMhz = 580,
            ramMb = 64, flashMb = 8, flashLayout = "8 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("MT7628 (2.4 GHz)", "MT7610E (5 GHz)"),
            extraFeatures = listOf("4x 100M LAN"), ethernetPorts = 5, gigabit = false,
            openwrtSupport = "yes (ramips/mt76x8)", stockLogin = "admin / admin",
            recovery = "TFTP recovery at 192.168.0.1",
        ),
        DeviceProfile(
            id = "tplink-tl-wr902ac-v3", brand = "TP-Link", model = "TL-WR902AC", revision = "v3",
            soc = "Qualcomm QCA9531", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 550,
            ramMb = 64, flashMb = 8, flashLayout = "8 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("QCA9531 (2.4 GHz)", "QCA9887 (5 GHz)"),
            extraFeatures = listOf("Travel router", "USB 2.0", "microSD"), usb = true, ethernetPorts = 2, gigabit = false,
            openwrtSupport = "yes (ath79)", stockLogin = "admin / admin",
            recovery = "TFTP recovery at 192.168.0.1",
        ),
        // ---------------------------------------------------------------- Netgear
        DeviceProfile(
            id = "netgear-r6220", brand = "Netgear", model = "R6220", revision = "v1",
            soc = "MediaTek MT7621ST", cpuFamily = CpuFamily.MIPSEL, cpuCores = 2, cpuMhz = 880,
            ramMb = 128, flashMb = 128, flashLayout = "128 MB NAND (UBI)", flashType = "NAND",
            bootloader = "U-Boot", wifiChips = listOf("MT7603E (2.4 GHz)", "MT7612E (5 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet", "USB 2.0"), usb = true, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (ramips/mt7621)", stockLogin = "admin / password",
            recovery = "Netgear TFTP recovery: hold reset, power on until power LED blinks green, serve image at 192.168.1.1",
            notes = "NAND device: flashing a NOR image will not boot.",
        ),
        DeviceProfile(
            id = "netgear-r6700-v3", brand = "Netgear", model = "R6700", revision = "v3",
            soc = "Broadcom BCM4709", cpuFamily = CpuFamily.ARM_LE, cpuCores = 2, cpuMhz = 1000,
            ramMb = 256, flashMb = 128, flashLayout = "128 MB NAND", flashType = "NAND",
            bootloader = "CFE", wifiChips = listOf("Broadcom BCM4360 (5 GHz)", "BCM4331 (2.4 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet", "USB 3.0"), usb = true, ethernetPorts = 5, gigabit = true,
            requiresSignedFirmware = true, openwrtSupport = "partial / risky (bcm53xx)",
            stockLogin = "admin / password", recovery = "Netgear TFTP recovery mode",
            notes = "Broadcom + signed stock firmware: most third-party images will be rejected by CFE.",
        ),
        DeviceProfile(
            id = "netgear-wndr3700-v4", brand = "Netgear", model = "WNDR3700", revision = "v4",
            soc = "Qualcomm/Atheros AR9344", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 560,
            ramMb = 128, flashMb = 128, flashLayout = "128 MB NAND", flashType = "NAND",
            bootloader = "U-Boot", wifiChips = listOf("AR9580 (ath9k, 5 GHz)", "AR9344 (ath9k, 2.4 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet", "USB 2.0"), usb = true, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (ath79)", stockLogin = "admin / password", recovery = "TFTP recovery at 192.168.1.1",
        ),
        DeviceProfile(
            id = "netgear-r7800", brand = "Netgear", model = "R7800", revision = "v1",
            soc = "Qualcomm IPQ8065", cpuFamily = CpuFamily.ARM_LE, cpuCores = 2, cpuMhz = 1700,
            ramMb = 512, flashMb = 128, flashLayout = "128 MB NAND (UBI)", flashType = "NAND",
            bootloader = "U-Boot", wifiChips = listOf("QCA9984 (ath10k, 5 GHz)", "QCA9980 (ath10k, 2.4 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet", "USB 3.0", "eSATA"), usb = true, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (ipq806x)", stockLogin = "admin / password", recovery = "TFTP recovery at 192.168.1.1",
        ),
        // ---------------------------------------------------------------- D-Link
        DeviceProfile(
            id = "dlink-dir-615-i3", brand = "D-Link", model = "DIR-615", revision = "rev I3",
            soc = "Qualcomm/Atheros AR9341", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 535,
            ramMb = 32, flashMb = 8, flashLayout = "8 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("AR9341 (2.4 GHz)"),
            ethernetPorts = 5, gigabit = false, openwrtSupport = "yes (ath79)",
            stockLogin = "admin / (blank)", recovery = "Emergency web recovery page at 192.168.0.1 (hold reset while powering on)",
            notes = "Many DIR-615 revisions exist with completely different CPUs - check the label.",
        ),
        DeviceProfile(
            id = "dlink-dir-825-b1", brand = "D-Link", model = "DIR-825", revision = "rev B1",
            soc = "Qualcomm/Atheros AR7161", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 680,
            ramMb = 64, flashMb = 16, flashLayout = "16 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("AR9220 (2.4 GHz)", "AR9223 (5 GHz)"),
            extraFeatures = listOf("USB 2.0"), usb = true, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (ath79)", stockLogin = "admin / admin", recovery = "Emergency web recovery page",
        ),
        // ---------------------------------------------------------------- ASUS
        DeviceProfile(
            id = "asus-rt-n16", brand = "ASUS", model = "RT-N16", revision = "",
            soc = "Broadcom BCM4718", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 2, cpuMhz = 480,
            ramMb = 128, flashMb = 32, flashLayout = "32 MB NOR", flashType = "NOR",
            bootloader = "CFE", wifiChips = listOf("Broadcom BCM4322 (2.4 GHz)", "BCM4321 (5 GHz)"),
            extraFeatures = listOf("Gigabit Ethernet", "2x USB 2.0"), usb = true, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (bcm47xx legacy)", stockLogin = "admin / admin",
            recovery = "ASUS Firmware Restoration tool / CFE mini-web server at 192.168.1.1",
        ),
        DeviceProfile(
            id = "asus-rt-ac68u", brand = "ASUS", model = "RT-AC68U", revision = "A1/A2",
            soc = "Broadcom BCM4708", cpuFamily = CpuFamily.ARM_LE, cpuCores = 2, cpuMhz = 800,
            ramMb = 256, flashMb = 128, flashLayout = "128 MB NAND", flashType = "NAND",
            bootloader = "CFE", wifiChips = listOf("BCM4360 (5 GHz)", "BCM4331 (2.4 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet", "USB 2.0", "USB 3.0"), usb = true, ethernetPorts = 5, gigabit = true,
            requiresSignedFirmware = false, openwrtSupport = "yes (bcm53xx)", stockLogin = "admin / admin",
            recovery = "ASUS rescue mode (hold reset + WPS while powering on), 192.168.1.1",
        ),
        DeviceProfile(
            id = "asus-rt-n12-d1", brand = "ASUS", model = "RT-N12", revision = "D1",
            soc = "Broadcom BCM5357", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 300,
            ramMb = 32, flashMb = 8, flashLayout = "8 MB NOR", flashType = "NOR",
            bootloader = "CFE", wifiChips = listOf("BCM5357 (2.4 GHz)"),
            ethernetPorts = 5, gigabit = false, openwrtSupport = "yes (bcm47xx)", stockLogin = "admin / admin",
            recovery = "ASUS rescue mode",
        ),
        // ---------------------------------------------------------------- Xiaomi / Redmi
        DeviceProfile(
            id = "xiaomi-mi-4a-gigabit", brand = "Xiaomi", model = "Mi Router 4A", revision = "Gigabit Edition",
            soc = "MediaTek MT7621A", cpuFamily = CpuFamily.MIPSEL, cpuCores = 2, cpuMhz = 880,
            ramMb = 128, flashMb = 16, flashLayout = "16 MB NOR", flashType = "NOR",
            bootloader = "U-Boot (bootloader is locked; needs vendor exploit to install OpenWrt)",
            wifiChips = listOf("MT7603E (2.4 GHz)", "MT7613 (5 GHz)"),
            extraFeatures = listOf("3x Gigabit Ethernet"), ethernetPorts = 3, gigabit = true,
            openwrtSupport = "yes (ramips/mt7621) after unlocking", stockLogin = "no default password",
            recovery = "Xiaomi recovery: hold reset, use the vendor recovery tool (if bootloader locked you may need serial/UART)",
            notes = "Xiaomi locks the bootloader: flashing anything that is not vendor-signed on an unlocked unit bricks it.",
        ),
        DeviceProfile(
            id = "xiaomi-mi-4c", brand = "Xiaomi", model = "Mi Router 4C", revision = "",
            soc = "MediaTek MT7628", cpuFamily = CpuFamily.MIPSEL, cpuCores = 1, cpuMhz = 580,
            ramMb = 64, flashMb = 16, flashLayout = "16 MB NOR", flashType = "NOR",
            bootloader = "U-Boot (locked)", wifiChips = listOf("MT7628 (2.4 GHz)"),
            ethernetPorts = 3, gigabit = false, openwrtSupport = "yes (ramips/mt76x8) after unlocking",
            stockLogin = "no default password", recovery = "Xiaomi recovery tool / UART",
        ),
        // ---------------------------------------------------------------- GL.iNet / Linksys / OpenWrt hardware
        DeviceProfile(
            id = "glinet-mt300n-v2", brand = "GL.iNet", model = "GL-MT300N-V2 (Mango)", revision = "",
            soc = "MediaTek MT7628", cpuFamily = CpuFamily.MIPSEL, cpuCores = 1, cpuMhz = 580,
            ramMb = 128, flashMb = 16, flashLayout = "16 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("MT7628 (2.4 GHz)"),
            extraFeatures = listOf("USB 2.0", "2x 100M Ethernet"), usb = true, ethernetPorts = 2, gigabit = false,
            openwrtSupport = "yes (ramips/mt76x8) - ships OpenWrt", stockLogin = "root / (set on first boot)",
            recovery = "U-Boot web recovery (192.168.1.1) + UART",
        ),
        DeviceProfile(
            id = "glinet-gl-mt1300", brand = "GL.iNet", model = "GL-MT1300 (Beryl)", revision = "",
            soc = "MediaTek MT7621A", cpuFamily = CpuFamily.MIPSEL, cpuCores = 2, cpuMhz = 880,
            ramMb = 256, flashMb = 32, flashLayout = "32 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("MT7603E (2.4 GHz)", "MT7615 (5 GHz)"),
            extraFeatures = listOf("3x Gigabit Ethernet", "USB 3.0"), usb = true, ethernetPorts = 3, gigabit = true,
            openwrtSupport = "yes (ramips/mt7621) - ships OpenWrt", stockLogin = "root / (set on first boot)",
            recovery = "U-Boot web recovery + UART",
        ),
        DeviceProfile(
            id = "linksys-ea6350-v3", brand = "Linksys", model = "EA6350", revision = "v3",
            soc = "Qualcomm IPQ4018", cpuFamily = CpuFamily.ARM_LE, cpuCores = 4, cpuMhz = 717,
            ramMb = 256, flashMb = 128, flashLayout = "128 MB NAND", flashType = "NAND",
            bootloader = "U-Boot", wifiChips = listOf("QCA4019 (ath10k, 2.4+5 GHz)"),
            extraFeatures = listOf("4x Gigabit Ethernet", "USB 3.0"), usb = true, ethernetPorts = 4, gigabit = true,
            openwrtSupport = "yes (ipq40xx)", stockLogin = "admin / (set on first boot)",
            recovery = "Linksys: power on while holding reset 10s + TFTP 192.168.1.1",
        ),
        DeviceProfile(
            id = "linksys-wrt3200acm", brand = "Linksys", model = "WRT3200ACM", revision = "",
            soc = "Marvell Armada 385", cpuFamily = CpuFamily.ARM_LE, cpuCores = 2, cpuMhz = 1866,
            ramMb = 512, flashMb = 256, flashLayout = "256 MB NAND", flashType = "NAND",
            bootloader = "U-Boot", wifiChips = listOf("Marvell 88W8964 (mwlwifi, 2.4+5 GHz)"),
            extraFeatures = listOf("5x Gigabit Ethernet", "USB 3.0", "eSATA"), usb = true, ethernetPorts = 5, gigabit = true,
            openwrtSupport = "yes (mvebu)", stockLogin = "admin / (set on first boot)",
            recovery = "Linksys dual-firmware: hold reset at power-on, TFTP recovery",
        ),
        DeviceProfile(
            id = "openwrt-one", brand = "OpenWrt", model = "One", revision = "",
            soc = "MediaTek MT7981B (Filogic 820)", cpuFamily = CpuFamily.AARCH64, cpuCores = 2, cpuMhz = 1300,
            ramMb = 1024, flashMb = 256, flashLayout = "256 MB NAND (UBI) + 16 MB NOR (bootloader fallback)", flashType = "NAND",
            bootloader = "U-Boot", wifiChips = listOf("MT7976 (2.4+5 GHz)"),
            extraFeatures = listOf("2.5G + 1G Ethernet", "USB 3.0", "M.2", "RTC"), usb = true, ethernetPorts = 2, gigabit = true,
            openwrtSupport = "yes (mediatek/filogic) - reference hardware", stockLogin = "root / (no password by default)",
            recovery = "NOR fallback bootloader + U-Boot web recovery + UART",
        ),
        DeviceProfile(
            id = "raspberry-pi-4b", brand = "Raspberry Pi", model = "4 Model B", revision = "",
            soc = "Broadcom BCM2711", cpuFamily = CpuFamily.AARCH64, cpuCores = 4, cpuMhz = 1500,
            ramMb = 4096, flashMb = 0, flashLayout = "microSD card (no internal flash - cannot be bricked by a bad image)", flashType = "SD",
            bootloader = "VideoCore bootloader (reads firmware from SD)", wifiChips = listOf("CYW43455 (brcmfmac, 2.4+5 GHz)"),
            extraFeatures = listOf("Gigabit Ethernet", "4x USB", "HDMI"), usb = true, ethernetPorts = 1, gigabit = true,
            openwrtSupport = "yes (bcm27xx/bcm2711)", stockLogin = "n/a",
            recovery = "Just rewrite the SD card - the safest device to experiment on",
            notes = "If you only want to *try* an image safely, this is the device to try it on.",
        ),
        // ---------------------------------------------------------------- generic / fallback
        DeviceProfile(
            id = "generic-mips-4-32", brand = "Generic", model = "MIPS 24Kc 4/32 device", revision = "",
            soc = "Generic Atheros/QCA MIPS 24Kc", cpuFamily = CpuFamily.MIPS_BE, cpuCores = 1, cpuMhz = 400,
            ramMb = 32, flashMb = 4, flashLayout = "4 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("unknown (ath9k-class)"),
            ethernetPorts = 5, gigabit = false, openwrtSupport = "depends on the exact model",
            stockLogin = "unknown", recovery = "TFTP recovery if the bootloader still runs",
            notes = "Typical 2010-2015 budget router: 4 MB flash only fits a stripped image.",
        ),
        DeviceProfile(
            id = "generic-mipsel-16-128", brand = "Generic", model = "MediaTek MT7621 16/128 device", revision = "",
            soc = "Generic MediaTek MT7621", cpuFamily = CpuFamily.MIPSEL, cpuCores = 2, cpuMhz = 880,
            ramMb = 128, flashMb = 16, flashLayout = "16 MB NOR", flashType = "NOR",
            bootloader = "U-Boot", wifiChips = listOf("unknown (mt76-class)"),
            ethernetPorts = 5, gigabit = true, openwrtSupport = "likely (ramips/mt7621)",
            stockLogin = "unknown", recovery = "TFTP recovery",
        ),
        DeviceProfile(
            id = "custom", brand = "My own router", model = "Custom / not in the list", revision = "",
            soc = "unknown", cpuFamily = CpuFamily.UNKNOWN, cpuCores = 1, cpuMhz = 0,
            ramMb = 0, flashMb = 0, flashLayout = "unknown", flashType = "UNKNOWN",
            bootloader = "unknown", wifiChips = emptyList(), openwrtSupport = "unknown",
            stockLogin = "unknown", recovery = "unknown", isCustom = true,
            notes = "Fill in what you know from the label; unknowns are reported as 'needs verification' instead of guessed.",
        ),
    )

    fun byId(id: String): DeviceProfile? = devices.firstOrNull { it.id == id }

    fun search(query: String): List<DeviceProfile> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return devices
        return devices.filter {
            it.brand.lowercase().contains(q) || it.model.lowercase().contains(q) ||
                "$q" == q && (it.model + it.revision).lowercase().contains(q)
        }
    }

    /** Groups for the picker UI. */
    fun byBrand(): Map<String, List<DeviceProfile>> = devices.groupBy { it.brand }
}
