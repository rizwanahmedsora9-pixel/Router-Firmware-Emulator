# Testing

## Engine self-test (plain JVM, no Android SDK)

    ./gradlew :engine:engineSelfTest

This runs `com.flashguard.engine.SelfTestKt`, which builds synthetic firmware images in-memory and
drives the whole pipeline against them. It exits non-zero when anything fails, so it is the CI gate
for analysis logic. Covered:

* identification: gzip, tar, TRX + vendor mining, U-Boot uImage in BOTH the real mkimage
  `image_header_t` layout (type@5/os@6/arch@7/name@28) and the legacy layout, with arch hints,
  high-entropy RAW/encrypted blob, UBI;
* containers: tar and cpio fixtures built byte-by-byte, a real-layout SquashFS 4.0 fixture
  (128-byte superblock, zlib data blocks, 6-byte directory entries - the mksquashfs/kernel
  format) that must list the full tree and read file content back, gzip round-trip;
* sandbox: variables/if/while scripting, service and port recording, hardware-touch detection
  (`mtd`), unknown-command accounting, `rm -rf /` confinement;
* full pipeline: an OpenWrt-like image on a matching device (must reach init and the web UI with
  no false red flags) and the same image on a NAND/CFE big-endian device (must go red);
* TP-Link TL-WR720N v1 (MT7620AT) and v2 (MT7628AN) images - TPLINK header + real mkimage uImage
  kernel + real-layout SquashFS: each must boot in the sandbox with zero red flags on its own
  revision and on the matching generic SoC profile, and must go **DO NOT FLASH** on the other
  revision (the SoC-family row, not the CPU row, raises the flag - both SoCs are big-endian MIPS);
* endianness model: ramips/MT76xx/ath79 markers are big-endian (a `mips_24kc` ramips image must
  NOT be flagged as a CPU mismatch on an MT7621 device), while a genuine little-endian image
  (brcm63xx/`mipsel`) must stay red on those devices;
* report export: JSON/Markdown structure, required sections;
* web UI lab: loopback HTTP server serving the image's login page with banner and status endpoint;
* device database consistency (every profile's fields agree with each other).

The hardware matrix carries a dedicated **SoC family (chip match)** row built from
`com.flashguard.engine.core.SocFamilies`: it resolves the image's SoC from device-tree strings,
kernel machine banners and a bounded scan of small rootfs files (`/etc/board-info`, banners, ...),
and the device's SoC from the profile. It only claims a verdict when *both* sides name a specific
SoC family, so generic/custom profiles never produce guessed mismatches. This is what makes
"same model, different hardware revision" files (WR720N v1 vs v2/v3/v4) fail loudly instead of
passing the architecture check.

Device database: the TL-WR720N ships all four hardware revisions (v1 = MT7620AT + MT7610, 4 MB
NOR; v2/v3 = MT7628AN, 4 MB NOR; v4 = MT7628AN, 8 MB NOR) plus the generic
`generic-mt7620-32-4` / `generic-mt7628-32-4` same-hardware profiles. Note: all MediaTek MT76xx
and Atheros/QCA router SoCs in the database are **big-endian** MIPS (their OpenWrt `ramips`/
`ath79` targets are BE); the little-endian MIPS lineage is Broadcom BCM63xx/Xburst.

## Real-image checks (CI only)

The workflow builds genuine fixtures with the official tools and feeds them to the same self-test:

    mksquashfs <root> out.sqfs -comp gzip
    mksquashfs <root> out.sqfs -comp xz
    tar -cf fixture.tar -C <root> .
    gzip -kc9 fixture.tar > fixture.tar.gz
    xz -kc9 fixture.tar > fixture.tar.xz
    xz --format=lzma -kc9 fixture.tar > fixture.tar.lzma

so SquashFS (metadata blocks, fragments and >block-size files) and the gzip/xz/lzma decoders are
exercised against files produced by the reference implementations rather than by our own code.

A real OpenWrt release image is downloaded and analysed as an informational check; its result is
printed into the build log and quoted in the release notes of every build.

## Android build

    ./gradlew :app:assembleDebug
    ./gradlew :app:assembleRelease   # signed when FLASHGUARD_KEYSTORE* env vars are set

CI builds both, publishes them to a GitHub release (tag `build-<run number>`) and uploads them as
the `FlashGuard-APKs` artifact.

## Local engine loop without Gradle

`tools/localcheck.sh` compiles the engine with a bare Kotlin compiler against a stubbed xz decoder
and runs the self-test, which is handy in environments without Maven access
(`tools/localstub/XzSupport.kt` is used there instead of the real file). It deletes the previous
jar first, so a compile failure is reported instead of silently running a stale build.
Any image paths passed after `--run` are analysed as real images (see the workflow above).

## Vendor fixture corpus (out-of-repo test tooling)

`/home/user/fwtest/run_demo.sh` (kept out of the repository on purpose) regenerates a corpus of
structurally real vendor containers with `make_fixtures.py` - byte-exact TPLINK/SHRS/CHK headers,
real mkimage uImages and real mksquashfs-layout SquashFS images - and runs the full pipeline over
every (image x device) pair in `VendorDemo.kt`, including the WR720N v1/v2 cross-revision checks.
Expected outcome: `CORPUS OK` with every vendor file booting on its own model and every
cross-SoC combination flagged.
