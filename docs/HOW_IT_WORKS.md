# How FlashGuard works

FlashGuard is two pieces: a **pure Kotlin/JVM engine** (`engine/`) that does all firmware work, and
an **Android UI** (`app/`) that drives it. Keeping the engine free of Android APIs means the same
code is exercised on a plain JVM by the CI self-tests, so analysis regressions are caught without a
phone in the loop.

## 1. Identify

`FirmwareIdentifier` sniffs the file by magic bytes and container structure, then walks nested
layers: TRX (`HDR0`), U-Boot legacy uImage, U-Boot FIT/FDT, Netgear CHK, TP-Link, D-Link/SERCOMM
headers, OpenWrt sysupgrade tarballs, tar/cpio/zip, SquashFS, cramfs, UBI/UBIFS, JFFS2, gzip/xz/
lzma/bzip2/zstd wrappers, raw flash dumps and encrypted blobs. It also mines the payload for
vendor, model, version and architecture strings, and records the SHA-256 so two files that claim
the same version can be told apart.

Everything found is stored as a tree of layers (offsets, sizes, formats) which the report prints -
so you can see exactly what the app believes the file is.

## 2. Unpack

`FirmwareUnpacker` pours the image into an in-RAM virtual filesystem (`VirtualFs`):

* containers: tar (ustar/GNU/PAX), cpio (newc/oldc), zip, SquashFS 4.0 (gzip/lzma/xz blocks,
  fragments and metadata blocks), TRX/uImage/CHK/TP-Link wrappers;
* wrappers: gzip, xz, lzma, bzip2 transparently decompressed first.

Hard limits protect the phone: 60 000 files, 48 MiB extracted total, 32 MiB per file, 1.5 GiB of
inflation, 4 MiB kept per file. Anything skipped is reported instead of silently ignored.

When none of the known headers match, a **deep scan** sweeps the whole blob (bounded to 64 MB) for a
payload at *any* offset - SquashFS, cpio, tar, gzip, xz, bzip2, zstd - and feeds what it finds back
into the pipeline. This is what opens a vendor image whose proprietary header the app cannot parse
but whose kernel/rootfs is a plain compressed stream. Candidates are validated before use (SquashFS
version, gzip method/flag bytes, tar size field) and a candidate that turns out not to be a valid
stream is logged as a dead end, never as a limitation of the firmware.

If *nothing* can be read, the result records that explicitly (`UnpackResult.inspected == false`) and
the rest of the pipeline switches to honesty mode: every content-based row becomes *needs
verification*, the Wi-Fi/USB/signature/coverage rows say "could not check" instead of "not
present", and the overall verdict is `CANNOT VERIFY` - never a claimed hardware mismatch.

After unpacking, `FirmwareFacts` reads the rootfs like a human would: `/etc/openwrt_release`,
banners, `/etc/init.d/*`, `/etc/config/*`, `/etc/passwd`/`shadow`, kernel modules, `www/` and
CGI handlers, nvram defaults. This produces the facts (distro, target, arch, kernel version,
drivers, users, web root, login pages, required flash size) that everything else is built on.

## 3. Emulate

`FirmwareEmulator` replays the image's **own boot logic** inside a sandboxed shell interpreter
(`SimShell`) with busybox-style builtins, `uci`/`nvram` models and a virtual filesystem:

* it executes the real boot order it finds in the image: `preinit`, `/etc/rcS.d/*`,
  `/etc/rc.d/S*`, `/etc/init.d/*` (via `rc.common` semantics, including `START=` priorities),
  `rc.local`;
* `start()`/`stop()` functions run for real (bounded), so `uhttpd -h /www -p 80`,
  `dnsmasq -C ...`, `dropbear`, `iptables`, `ip addr add ...`, `mtd` (recorded as a hardware
  touch, never performed) all leave the same traces a real boot would;
* every step is bounded: 250 000 shell steps, 20 s wall clock, loop-iteration and call-depth caps.
  The sandbox cannot escape the virtual filesystem - `rm -rf /` there deletes nothing real, and
  no ARM/MIPS instruction is ever executed.

Output: a stage-by-stage boot chain (header -> kernel -> rootfs -> init -> services -> web UI),
a boot log, the list of services with the ports they bind, created files, interfaces, variables,
and honest notes about anything that could not be simulated.

## 4. Serve the emulated web UI

`WebUiLab` inventories the image's `www/` tree: pages, CGI handlers, login forms (field names and
action URLs are parsed), feature groups (System, Wi-Fi, VPN, USB, ...) and the doc root. It can
then serve those pages over **loopback only** (`127.0.0.1`, random port) with a small banner, and
model the firmware's own CGI responses (`status`, `login`, `console`). The Android WebView loads
that loopback URL, so you can click through the firmware's UI exactly as it ships - offline.

## 5. Compare against your hardware

`HardwareMatrix` turns the facts into rows: architecture, flash size, flash type (NOR/NAND), boot
loader format, signature requirements, Wi-Fi/USB extras, RAM, device tree/board strings, install
method (stock vs sysupgrade), whole-flash scope, static boot evidence and the recovery path for the
selected model. Verdicts: `INCOMPATIBLE` (red), `PARTIAL`/`UNVERIFIED` (amber), `COMPATIBLE`
(green). Any red row forces **DO NOT FLASH**; amber rows force **NEEDS MANUAL REVIEW**; only an
all-green matrix yields **SAFE TO FLASH AFTER BACKUP**.

Two rules keep the verdicts honest:

* **A row may only go red on evidence, never on missing evidence.** "The image ships no wireless
  drivers" is a fact about a file we read; for a file we could not read it becomes *needs
  verification* with the reason. Genuine mismatches (wrong SoC, NAND image on NOR, file bigger than
  the flash chip) stay red even for an unreadable blob, because their evidence is in the bytes we do
  have.
* **Unverified rows are not risk.** They contribute little to the score and cap it at 55, so an
  image nothing could be read from can never show 100/100 - that number is reserved for images with
  a proven incompatibility. The overall verdict for "no mismatch, but nothing readable" is
  `CANNOT VERIFY`, which is deliberately distinct from `DO NOT FLASH - hardware mismatch detected`.

Under the matrix, `Heuristics` adds security/quality findings: empty root password, default
accounts, telnet, WPS, hardcoded credentials, world-writable web files, old kernels
(< 4.4), missing CSRF on login, plaintext Wi-Fi keys, TR-069 hooks.

## 6. Report and live test

`Report` renders everything as Markdown (for humans) and JSON (for tooling), including the
evidence behind each verdict, the emulated boot log, the feature inventory, the security findings
and concrete next steps. `StabilityProbe` performs the optional read-only live check against a
router on the LAN: repeated GETs for latency/stability, banner and login-form detection, optional
default-credential attempt, and a hard-coded blocklist so that reboot/reset/upgrade/flash/erase/
restore endpoints can never be requested.
