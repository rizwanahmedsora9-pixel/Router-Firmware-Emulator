# FlashGuard - Router-Firmware-Emulator

**Test *any* router firmware on your Android phone before it ever touches a flash chip.**

Give FlashGuard a firmware file - a vendor `.bin`/`.img`/`.trx`/`.chk`/`.ubi`, an OpenWrt
sysupgrade tarball, a gzip/xz/lzma stream, a SquashFS image or a raw flash dump - and it will:

1. **Identify it** (format, vendor, model, version, architecture, container layers, SHA-256).
2. **Unpack it** on-device into a virtual root filesystem (tar, cpio, zip, SquashFS, TRX,
   uImage/FIT, gzip/xz/lzma ...).
3. **Emulate its boot logic** in a sandboxed shell: the image's own `/etc/init.d`, `/etc/rc.d`,
   `rc.common`, `nvram`/`uci` calls actually run (bounded and simulated - no CPU instructions of
   ARM/MIPS binaries are executed, nothing real is written).
4. **Prove what comes up**: bootloader header → kernel → rootfs → init → services → web UI, plus
   the **login page** the firmware ships.
5. **Serve that web UI** from a loopback-only server inside the app so you can click through the
   login page and the feature pages (in a WebView) before flashing anything.
6. **Score every feature against your exact router model** and mark hardware-incompatible parts in
   **red** - the CPU family, flash type/size, bootloader, Wi-Fi chipset, RAM, device tree and
   signature rules that turn a wrong image into a brick.
7. **Check a live router** on your LAN (read-only) to confirm it is up, that the login page shows,
   what works after login, and whether it stays stable.
8. **Export a report** (Markdown + JSON) with every verdict, the evidence behind it and the next
   steps - including the recovery path for your model.

> The point: *if it survives the emulator and the matrix is green, you flash with evidence - not hope.*

---

## Install

Every push builds and publishes an installable APK:

* **Releases page (recommended):** <https://github.com/rizwanahmedsora9-pixel/Router-Firmware-Emulator/releases>
  (build tags `build-N`: `app-debug.apk` and a signed `app-release.apk`)
* **Actions artifacts:** any green run under *Actions → Android build & engine tests → FlashGuard-APKs*.

Requirements: Android 7.0 (API 24) or newer. No root needed. The app works fully offline; the only
network use is the optional read-only check against your own router on the LAN.

## Quick start (2 minutes)

1. Open the app → the login screen appears (local app lock, default `admin` / `admin`).
2. Tab **My router** → pick your exact model **and revision** (e.g. *Archer C6 v2*, *TL-WR841N
   v13/v14*, *R6220*). Anything not listed can be added as a custom profile.
3. Tab **Analyze** → *Choose firmware file* (or *load the built-in demo image* if you just want to
   see the whole pipeline immediately) → **Run the safety test**.
4. Read the result:
   * **green** = the checks that matter all passed,
   * **amber** = things a static test cannot prove (verify manually),
   * **red** = **hardware-incompatible - do not flash this**,
   * *could not verify* = nothing inside the file could be unpacked (raw/vendor-encrypted blob),
     so there is no evidence either way. That is reported as its own verdict, **not** as a hardware
     mismatch - the next steps tell you how to find out what the file actually is.
5. Tab **Emulator** → *Open the emulated login page* to click through the firmware's own UI
   (the emulated router asks for `admin` / `admin` in a popup first, like the real thing).
6. Tab **Live test** → test the router you already have (before/after flashing) - read-only.
7. Tab **Report** → share or copy the full Markdown/JSON report.

Then, and only then, flash using the vendor/OpenWrt upgrade page - with a full backup taken and
your model's recovery procedure at hand.

## What the compatibility matrix checks

| Check | What a red row means |
|---|---|
| CPU architecture | image built for MIPS/ARM/x86 that your SoC cannot execute |
| Flash size | uncompressed rootfs larger than your whole flash (write fails mid-way) |
| Flash type (NOR vs NAND) | NAND/UBI image on a NOR device (or the reverse) - bootloader finds no kernel |
| Bootloader format | CFE device fed a U-Boot image (or the reverse) |
| Vendor signature | device requires signed firmware; image is not signed |
| Wi-Fi hardware | drivers for other chipsets only - radio never comes up |
| USB / storage | image needs USB the device does not have (amber: harmless) |
| RAM | target class needs more RAM than the device has |
| Device tree / board name | image's board strings name a different model (LAN/WAN/LED mapping differs) |
| Install method | sysupgrade image while the router still runs stock firmware |
| Image scope | whole-flash dump (erases the bootloader - the classic irreversible brick) |
| Static boot test | sandbox could not drive the image to a running system |
| Recovery path | how to un-brick this model if it goes wrong |

## Repository layout

```
engine/   pure Kotlin/JVM firmware-analysis + emulation engine (no Android dependencies)
app/      Android UI: login, dashboard, device picker, matrix, emulator WebView, probe, reports
tools/    localcheck.sh (fast local engine compile+test) and the local xz stub
docs/     user guide, how it works, limitations
```

The engine runs on a plain JVM, so the whole analysis pipeline is testable in CI without a device:
`./gradlew :engine:engineSelfTest` grades 20+ checks including SquashFS/xz/lzma fixtures built with
`mksquashfs`, a real OpenWrt release image, and the sandbox's escape attempts.

## Honesty rules baked into the design

* Static emulation reproduces the firmware's **own init/config logic**; it does not execute ARM/MIPS
  binaries and cannot touch real hardware. Anything that can only be answered by real silicon is
  reported as *unverified*, never as "works".
* A red row needs **positive evidence**, never the absence of it. "This image ships no wireless
  drivers" is only asserted for an image the engine actually unpacked; if nothing could be read, the
  row becomes *needs verification* with the reason, and the verdict is *could not verify* - calling
  an unreadable file a "hardware mismatch" (for example your own stock image) is a false alarm that
  teaches people to ignore the red verdicts that matter. Genuine mismatches - wrong SoC, NAND image
  on NOR, a file larger than the whole flash chip - stay red regardless, because their evidence is in
  the bytes we do have.
* Vendor-signed/encrypted images are reported as opaque instead of guessed at.
* Unknown devices are reported as *needs verification* instead of being assumed compatible.
* The app never flashes anything. It has no write path to a router: the live check is GET-only,
  plus an optional POST to the login form itself.

See `docs/LIMITATIONS.md` for the full list of what this tool cannot tell you.

## Building

```bash
# engine tests on a plain JVM (no Android SDK needed)
./gradlew :engine:engineSelfTest

# APKs
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease   # signed when FLASHGUARD_KEYSTORE* env vars are set
```

GitHub Actions does the same on every push and publishes the APKs as a release.
