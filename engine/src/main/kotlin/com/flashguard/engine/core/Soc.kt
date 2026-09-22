package com.flashguard.engine.core

/**
 * SoC family table used to cross-check "which chip is this image built for" against "which chip
 * is in the router".
 *
 * Different SoCs of the same CPU architecture are NOT interchangeable: a kernel built for a
 * MT7620AT board will not find its drivers/interrupts/flash layout on a MT7628AN board. This is
 * exactly why the same model with different hardware revisions cannot flash each other's
 * firmware - the classic case is the TP-Link TL-WR720N, where v1 ships an MT7620AT and
 * v2/v3/v4 ship a MT7628AN.
 *
 * Matching is deliberately prefix-based on alphanumeric tokens: evidence strings arrive as
 * "MediaTek MT7620AT", "mediatek,mt7620a-soc", "ramips/mt7621", "TP-Link TL-WR720N v1 (MT7620)"
 * and all of them must resolve to the same family.
 */
object SocFamilies {

    data class Family(val name: String, val vendor: String, val prefixes: List<String>) {
        fun matchesToken(token: String): Boolean = prefixes.any { token.startsWith(it) }
    }

    val FAMILIES: List<Family> = listOf(
        // MediaTek Ralink / MT series (all MIPS big-endian 24Kc)
        Family("MediaTek MT7620", "MediaTek", listOf("mt7620")),
        Family("MediaTek MT7621", "MediaTek", listOf("mt7621")),
        Family("MediaTek MT7628", "MediaTek", listOf("mt7628")),
        Family("MediaTek MT7688", "MediaTek", listOf("mt7688")),
        Family("MediaTek MT798x", "MediaTek", listOf("mt7981", "mt7986", "mt7988")),
        // Atheros / Qualcomm
        Family("Qualcomm QCA9531 (AR9341)", "Qualcomm", listOf("qca9531", "ar9341")),
        Family("Qualcomm QCA9558 (AR9344)", "Qualcomm", listOf("qca9558", "ar9344")),
        Family("Qualcomm QCA9563 (AR9563)", "Qualcomm", listOf("qca9563", "qca9561", "ar9561")),
        Family("Qualcomm AR7161", "Qualcomm", listOf("ar7161", "ar7241")),
        Family("Qualcomm AR7240", "Qualcomm", listOf("ar7240")),
        Family("Qualcomm IPQ40xx", "Qualcomm", listOf("ipq4018", "ipq4019", "ipq40xx")),
        Family("Qualcomm IPQ806x", "Qualcomm", listOf("ipq8064", "ipq8065", "ipq806x")),
        // Broadcom
        Family("Broadcom BCM2711", "Broadcom", listOf("bcm2711")),
        Family("Broadcom BCM4708", "Broadcom", listOf("bcm4708")),
        Family("Broadcom BCM4709", "Broadcom", listOf("bcm4709")),
        Family("Broadcom BCM4718", "Broadcom", listOf("bcm4718")),
        Family("Broadcom BCM4727", "Broadcom", listOf("bcm4727")),
        Family("Broadcom BCM5357", "Broadcom", listOf("bcm5357")),
        Family("Broadcom BCM63xx", "Broadcom", listOf("bcm63138", "bcm63268", "bcm6358")),
        // Marvell / Allwinner / Realtek
        Family("Marvell Armada 38x", "Marvell", listOf("armada380", "armada385", "armada388")),
        Family("Marvell Armada 37xx", "Marvell", listOf("armada3700", "armada3720")),
        Family("Allwinner Sun8i", "Allwinner", listOf("sun8i")),
        Family("Realtek RTL819x/836x", "Realtek", listOf("rtl8196", "rtl8367")),
    )

    /** Splits text into lowercase alphanumeric tokens: "TP-LINK,TL-WR720N-V1" -> [tplink, tl, wr720n, v1]. */
    fun tokens(text: String): List<String> =
        Regex("[a-z0-9]+").findAll(text.lowercase()).map { it.value }.toList()

    /** The first SoC family any token of [text] points at, or null when no specific SoC is named. */
    fun fromText(text: String): Family? {
        val toks = tokens(text)
        if (toks.isEmpty()) return null
        return FAMILIES.firstOrNull { f -> toks.any { f.matchesToken(it) } }
    }
}
