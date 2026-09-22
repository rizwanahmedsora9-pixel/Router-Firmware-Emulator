package com.flashguard.engine.tools

import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream

/**
 * Builds a small synthetic "OpenWrt-like" firmware image in memory.
 *
 * Purpose: let a user (or a reviewer) see the whole pipeline - identify, unpack, emulate the init
 * scripts, reach the login page, build the compatibility report - without needing a real firmware
 * file on hand. It is *not* a real router firmware and is clearly labelled as a demo everywhere.
 */
object DemoFirmware {

    const val DISPLAY_NAME = "demo-openwrt-ramips-mt7621.tar.gz"

    /** Returns (fileName, bytes) for gzip(tar(rootfs)) demo image. */
    fun build(variant: Variant = Variant.OPENWRT_MIPSEL): ByteArray {
        val entries = ArrayList<Pair<String, ByteArray>>()
        val dirs = mutableListOf(
            "etc", "etc/init.d", "etc/config", "etc/rc.d", "www", "www/cgi-bin", "lib",
            "lib/modules/4.14.241", "usr", "usr/sbin", "usr/lib/opkg", "sbin", "tmp",
        )

        val (distro, target, arch, soc, vendorName) = when (variant) {
            // A real little-endian MIPS build: the brcm63xx target (BCM63xx SoCs are mipsel).
            // ramips/mt76xx images are BIG-endian, so an "mipsel MT7621" demo would be
            // a firmware that does not exist.
            Variant.OPENWRT_MIPSEL -> listOf("OpenWrt", "brcm63xx/generic", "mipsel", "Broadcom BCM6358", "OpenWrt 23.05.3")
            Variant.OPENWRT_MIPSBE -> listOf("OpenWrt", "ath79/generic", "mips_24kc", "Qualcomm QCA9531", "OpenWrt 23.05.3")
            Variant.DDWRT_MIPSBE -> listOf("DD-WRT", "broadcom", "mips", "Broadcom BCM4718", "DD-WRT v3.0-r54216")
        }

        entries += "etc/openwrt_release" to """
            DISTRIB_ID='$distro'
            DISTRIB_RELEASE='23.05.3'
            DISTRIB_TARGET='$target'
            DISTRIB_ARCH='$arch'
            DISTRIB_DESCRIPTION='$vendorName'
        """.trimIndent().toByteArray()

        entries += "etc/banner" to """
             _______                     ________        __
            |       |.-----.-----.-----.|  |  |  |.----.|  |_
            |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
            |_______||   __|_____|__|__||________||__|  |____|
                     |__| $vendorName
            Target: $target   SoC: $soc
        """.trimIndent().toByteArray()

        entries += "etc/init.d/network" to """
            #!/bin/sh /etc/rc.common
            START=20
            start() {
                echo "configuring network"
                ip addr add 192.168.1.1/24 dev br-lan
                ip link set br-lan up
                ifconfig eth0 up
                export lan_ipaddr=192.168.1.1
                hostname OpenWrt
            }
        """.trimIndent().toByteArray()

        entries += "etc/init.d/dnsmasq" to """
            #!/bin/sh /etc/rc.common
            START=19
            start() {
                dnsmasq -C /var/etc/dnsmasq.conf
            }
        """.trimIndent().toByteArray()

        entries += "etc/init.d/dropbear" to """
            #!/bin/sh /etc/rc.common
            START=30
            start() {
                /usr/sbin/dropbear -p 22
            }
        """.trimIndent().toByteArray()

        entries += "etc/init.d/uhttpd" to """
            #!/bin/sh /etc/rc.common
            START=50
            start() {
                echo "starting web server"
                uhttpd -h /www -p 80
            }
        """.trimIndent().toByteArray()

        entries += "etc/rc.d/S20network" to "#!/bin/sh\n/etc/init.d/network start\n".toByteArray()
        entries += "etc/rc.d/S19dnsmasq" to "#!/bin/sh\n/etc/init.d/dnsmasq start\n".toByteArray()
        entries += "etc/rc.d/S30dropbear" to "#!/bin/sh\n/etc/init.d/dropbear start\n".toByteArray()
        entries += "etc/rc.d/S50uhttpd" to "#!/bin/sh\n/etc/init.d/uhttpd start\n".toByteArray()

        entries += "www/login.html" to """
            <!DOCTYPE html><html><head><meta charset="utf-8"><title>Router Login</title></head>
            <body><h2>Router administration</h2>
            <form method="post" action="/cgi-bin/luci">
              <label>Username <input type="text" name="luci_username"></label><br>
              <label>Password <input type="password" name="luci_password"></label><br>
              <input type="submit" value="Log in">
            </form></body></html>
        """.trimIndent().toByteArray()

        entries += "www/index.html" to "<html><head><title>Status</title></head><body>System status page</body></html>".toByteArray()
        entries += "www/wifi.html" to "<html><head><title>Wireless</title></head><body>Wi-Fi configuration</body></html>".toByteArray()
        entries += "www/vpn.html" to "<html><head><title>VPN</title></head><body>OpenVPN / WireGuard</body></html>".toByteArray()
        entries += "www/usb.html" to "<html><head><title>USB</title></head><body>USB storage and printer</body></html>".toByteArray()
        entries += "www/cgi-bin/luci" to "#!/usr/bin/lua\n-- LuCI dispatcher (native, not executed in static preview)\n".toByteArray()

        entries += "etc/passwd" to "root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\n".toByteArray()
        entries += "etc/shadow" to "root:\$1\$demo\$abcdefghijklmnopqrst:19000:0:99999:7:::\n".toByteArray()
        entries += "etc/config/network" to "config interface 'lan'\n\toption ifname 'br-lan'\n\toption proto 'static'\n\toption ipaddr '192.168.1.1'\n".toByteArray()
        entries += "etc/config/wireless" to "config wifi-device 'radio0'\n\toption type 'mac80211'\n\toption channel '6'\n\toption hwmode '11g'\nconfig wifi-iface\n\toption ssid 'OpenWrt'\n\toption encryption 'none'\n".toByteArray()

        entries += "usr/lib/opkg/status" to buildString {
            for (p in listOf("base-files", "busybox", "dnsmasq", "dropbear", "firewall4", "luci", "luci-base", "uhttpd", "kmod-mt7603", "kmod-mt76x2", "kmod-usb-storage")) {
                append("Package: $p\nVersion: 23.05.3-1\nStatus: install user installed\n\n")
            }
        }.toByteArray()

        entries += "lib/modules/4.14.241/mt7603e.ko" to ByteArray(2048) { (it % 251).toByte() }
        entries += "lib/modules/4.14.241/mt76x2e.ko" to ByteArray(1536) { (it % 199).toByte() }
        entries += "lib/modules/4.14.241/usb-storage.ko" to ByteArray(512) { 7 }
        entries += "lib/modules/4.14.241/xt_CT.ko" to ByteArray(384) { 11 }
        // ELF-ish placeholder binaries: contain NUL bytes so the engine treats them as
        // native executables (simulated as started-services) instead of trying to parse them as shell scripts.
        entries += "usr/sbin/uhttpd" to pseudoElf(8192)
        entries += "usr/sbin/dnsmasq" to pseudoElf(8192)
        entries += "usr/sbin/dropbear" to pseudoElf(8192)
        entries += "sbin/mtd" to pseudoElf(256)
        entries += "bin/busybox" to pseudoElf(16384)
        entries += "usr/bin/lua" to pseudoElf(4096)

        val tar = buildTar(entries, dirs)
        val bos = ByteArrayOutputStream()
        GZIPOutputStream(bos).use { it.write(tar) }
        return bos.toByteArray()
    }

    enum class Variant(val label: String) {
        OPENWRT_MIPSEL("OpenWrt 23.05 (mipsel / MT7621 - Archer C6, R6220, Mi 4A Gigabit)"),
        OPENWRT_MIPSBE("OpenWrt 23.05 (MIPS big-endian / ath79 - Archer C7, WR841N v13)"),
        DDWRT_MIPSBE("DD-WRT (Broadcom MIPS big-endian - RT-N16, WNDR3700 v4)"),
    }

    /** A byte pattern that looks like a stripped ARM/MIPS binary to the heuristics. */
    private fun pseudoElf(size: Int): ByteArray {
        val b = ByteArray(size)
        val magic = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
        System.arraycopy(magic, 0, b, 0, 4)
        for (i in 16 until size) {
            b[i] = when {
                i % 64 == 0 -> 0
                i % 7 == 0 -> (0x80 + (i % 0x60)).toByte()
                else -> (i % 256).toByte()
            }
        }
        return b
    }

    // ---------------------------------------------------------------- tar writing

    private fun header(name: String, size: Int, mode: Int, isDir: Boolean): ByteArray {
        val h = ByteArray(512)
        fun put(offset: Int, text: String, max: Int) {
            val bytes = text.toByteArray(Charsets.ISO_8859_1)
            System.arraycopy(bytes, 0, h, offset, minOf(bytes.size, max))
        }
        put(0, name, 100)
        put(100, String.format("%07o", mode), 8)
        put(108, "0000000", 8)
        put(116, "0000000", 8)
        put(124, String.format("%011o", if (isDir) 0 else size), 12)
        put(136, String.format("%011o", 0), 12)
        put(148, "        ", 8)
        h[156] = (if (isDir) '5' else '0').code.toByte()
        put(257, "ustar", 6)
        put(263, "00", 2)
        put(265, "root", 32)
        put(297, "root", 32)
        var sum = 0
        for (b in h) sum += b.toInt() and 0xFF
        put(148, String.format("%06o\u0000 ", sum), 8)
        return h
    }

    private fun buildTar(entries: List<Pair<String, ByteArray>>, dirs: List<String>): ByteArray {
        val out = ByteArrayOutputStream()
        for (d in dirs) out.write(header(d, 0, 0b111101101, isDir = true))
        for ((name, content) in entries) {
            out.write(header(name, content.size, 0b110100100, isDir = false))
            out.write(content)
            val pad = (512 - content.size % 512) % 512
            if (pad > 0) out.write(ByteArray(pad))
        }
        out.write(ByteArray(1024))
        return out.toByteArray()
    }
}
