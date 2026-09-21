# Testing

## Engine self-test (plain JVM, no Android SDK)

    ./gradlew :engine:engineSelfTest

This runs `com.flashguard.engine.SelfTestKt`, which builds synthetic firmware images in-memory and
drives the whole pipeline against them. It exits non-zero when anything fails, so it is the CI gate
for analysis logic. Covered:

* identification: gzip, tar, TRX + vendor mining, U-Boot uImage with arch hints, high-entropy
  RAW/encrypted blob, UBI;
* containers: tar and cpio fixtures built byte-by-byte, gzip round-trip;
* sandbox: variables/if/while scripting, service and port recording, hardware-touch detection
  (`mtd`), unknown-command accounting, `rm -rf /` confinement;
* full pipeline: an OpenWrt-like image on a matching device (must reach init and the web UI with
  no false red flags) and the same image on a NAND/CFE big-endian device (must go red);
* report export: JSON/Markdown structure, required sections;
* web UI lab: loopback HTTP server serving the image's login page with banner and status endpoint;
* device database consistency (every profile's fields agree with each other).

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
(`tools/localstub/XzSupport.kt` is used there instead of the real file).
