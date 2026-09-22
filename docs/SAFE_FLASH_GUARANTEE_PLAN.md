# Safe Flash Authorization Plan

## Purpose

FlashGuard must not describe static analysis or WebView emulation as a guarantee that a physical router can safely accept firmware. The product goal is a **conditional, evidence-backed flash authorization**: flashing is permitted only when all required hardware, image, partition, recovery, and test conditions are verified. Unknown or incomplete evidence must block flashing.

An absolute guarantee for arbitrary routers and arbitrary firmware is not technically possible. A defensible guarantee can be provided only for a closed set of verified router profiles and firmware hashes.

## Current Boundary

The current application:

- Extracts and analyzes firmware files.
- Inspects architecture, target information, filesystems, packages, kernel modules, boot information, and web assets.
- Reconstructs or models a firmware web UI on loopback.
- Serves static pages where available.
- Models native CGI/HTTP responses that cannot execute directly on Android.

The emulator is **not** a hardware-equivalent router. It does not prove that the bootloader, flash chip, kernel drivers, wireless chipset, Ethernet switch, GPIO, NVRAM, partition layout, or vendor upgrade process will work on physical hardware. Its result must never independently authorize flashing.

## Product Safety Rules

1. Static analysis may identify compatibility evidence, but may not claim a physical-flash guarantee.
2. Emulator output is for inspection and behavior preview only.
3. Missing hardware identity, partition data, image validation, or recovery evidence results in a hard block.
4. Only explicitly verified router profiles and firmware hashes may reach an authorized state.
5. Every authorization must record its evidence, tool version, profile version, firmware hash, and remaining limitations.
6. The app must never silently downgrade from verified authorization to a weaker compatibility result.

## Verification Pipeline

### 1. Exact hardware identity

Capture and verify:

- Exact model and hardware revision.
- Region and board ID.
- SoC and CPU architecture.
- RAM and flash capacity.
- Bootloader version.
- Current firmware version.
- Actual partition table and offsets.
- Vendor image format requirements.

If the exact identity cannot be established, return **Flash blocked: hardware identity unverified**.

### 2. Firmware validation

Validate:

- Cryptographic checksum and vendor signature where available.
- Image magic and vendor header.
- Model, board ID, hardware revision, and region.
- Architecture, kernel addresses, and entry point.
- Kernel and root filesystem integrity.
- Compression and filesystem formats.
- Image size against the target partition.
- Partition offsets and erase boundaries.
- Upgrade type: factory, recovery, or sysupgrade.
- Required upgrade path and rollback metadata.

### 3. Signed hardware profile database

Maintain versioned, signed profiles containing:

- Hardware identity and partition map.
- Supported image formats.
- Known-good firmware hashes.
- Known-bad hashes and rejection rules.
- Required upgrade paths.
- Verified recovery procedure.
- Hardware-in-the-loop test evidence.

A generic model name is insufficient; the profile must match the complete hardware identity.

### 4. Hardware-in-the-loop testing

For each supported profile, test on sacrificial physical devices:

- Real upgrade method.
- Successful boot and reboot persistence.
- Network interfaces and wireless operation.
- Web UI and management access.
- Factory reset.
- Recovery mode.
- Partition integrity and read-back verification.
- Power interruption at safe test points.
- Rollback or dual-bank behavior where supported.

Record device revision, firmware hash, test date, test results, and recovery evidence.

### 5. Recovery-first authorization

Before permitting a flash, require a verified recovery method such as TFTP, serial/U-Boot, vendor emergency recovery, or a tested dual-bank rollback. If no recovery method is known and verified, flashing is blocked.

### 6. Transactional flashing

Where the hardware allows it:

1. Back up the working firmware and configuration.
2. Re-validate the image immediately before transfer.
3. Transfer to temporary storage.
4. Verify the transferred checksum.
5. Write only the authorized partition.
6. Read back and verify the written image.
7. Reboot only after verification.
8. Confirm successful boot and management access.
9. Roll back automatically when supported and boot verification fails.

Never erase the only known-good boot path before the replacement is confirmed.

## Authorization Levels

### Verified

Allowed only when exact hardware identity, image integrity, partition compatibility, recovery, and physical test evidence all match.

### Strong compatibility

Static validation is complete, but the exact combination lacks physical test evidence. Display the findings, but keep flashing blocked by default.

### Emulator only

The image can be inspected or its modeled UI can be opened. No flashing authorization is possible.

### Unsafe

Any corruption, mismatch, unknown partition layout, unsupported format, or missing recovery path. Flashing is hard blocked.

## Required UI Language

Replace optimistic labels such as `Safe for flash` with:

- `Flash authorization: VERIFIED`
- `Flash authorization: BLOCKED`
- `Static compatibility only`
- `Emulation only — no hardware guarantee`

Every result must show:

- Exact hardware profile and profile version.
- Firmware filename and cryptographic hash.
- Evidence that passed.
- Evidence that is missing.
- Recovery method.
- Physical test references.
- Remaining risks and limitations.
- The reason for authorization or blocking.

The emulator must display a persistent warning:

> This is a reconstructed/modelled environment. It does not prove hardware compatibility and cannot authorize flashing.

## Implementation Phases

### Phase 1 — Safety wording and hard gates

- Remove or qualify all unconditional “safe” language.
- Add explicit emulator limitations.
- Separate static analysis, emulation, and flash authorization states.
- Make missing evidence block authorization.
- Add tests for unsafe defaults.

### Phase 2 — Evidence model

- Add structured hardware profiles.
- Add firmware hash and validation records.
- Add partition and recovery evidence fields.
- Produce a signed, auditable authorization report.

### Phase 3 — Verified profile database

- Build profiles for a small number of supported routers.
- Add known-good and known-bad image hashes.
- Add profile versioning and signature verification.
- Refuse unknown profiles and modified images.

### Phase 4 — Hardware test program

- Establish sacrificial test hardware.
- Automate flashing, boot checks, management checks, recovery, and read-back verification.
- Store reproducible test evidence.
- Permit `VERIFIED` only for tested profile/image combinations.

### Phase 5 — Controlled flashing

- Implement recovery-first checks.
- Implement transactional flashing where possible.
- Add preflight confirmation showing every evidence item.
- Require explicit user confirmation only after all gates pass.
- Add automatic rollback where the hardware supports it.

## Definition of Done

The app may show `Flash authorization: VERIFIED` only when:

- The exact physical hardware identity is verified.
- The firmware hash matches a signed, tested record.
- The image format and partition layout match.
- The upgrade path is supported.
- A recovery method is verified.
- Hardware-in-the-loop tests passed for that profile and image.
- The authorization report records all evidence and limitations.

Until all of these conditions are met, the app must remain an analysis and emulation tool and must block any claim that flashing is guaranteed safe.
