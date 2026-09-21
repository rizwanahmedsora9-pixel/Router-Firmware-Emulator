# What FlashGuard can and cannot tell you

Being explicit about this is the difference between a useful pre-flight check and a false sense of
security. Read this before trusting a green verdict.

## What it genuinely does

* Parses real firmware containers and root filesystems (SquashFS incl. fragments and metadata
  blocks, tar/cpio/zip, TRX, uImage/FIT, CHK, sysupgrade, gzip/xz/lzma/bzip2).
* Runs the image's own init scripts, `rc.common` logic, `uci`/`nvram` calls and service startups
  in a bounded sandbox, and reports the boot chain, services, files and web UI it produced.
* Compares the image against a specific hardware profile and marks hardware conflicts red with the
  reason.
* Serves the firmware's real web pages over loopback so the UI can be inspected before flashing.
* Produces a reproducible report (SHA-256, facts, matrix, findings, boot log).

## What it cannot do

* **It does not execute ARM/MIPS machine code.** Emulation is of the firmware's scripting/config
  logic, not of its binaries. A daemon that only misbehaves inside its compiled code will not be
  caught here.
* **It cannot prove RF behaviour.** Aerial calibration, channel plans and regulatory limits live in
  hardware; a green Wi-Fi row means "the right drivers and firmware files are present", not "the
  radio will work".
* **It cannot prove flash timing.** Some bricks come from write-time failures (bad erase-block
  handling, power loss). The matrix can flag scope and layout mistakes, not physical write errors.
* **Vendor-signed/encrypted images stay opaque.** If the payload cannot be decrypted, FlashGuard
  reports that instead of guessing, and the matrix will show unverified rows.
* **Unknown devices are not guessed.** A profile you invent is only as accurate as its numbers.
* **Amber is not "probably fine".** It means "a static test cannot answer this" - check it
  manually, as the row's guidance says.
* **The live test is read-only by design.** It cannot and will not flash, reboot or reset anything.
  Flashing is done by the vendor/OpenWrt upgrade page or recovery mode, at your own risk.

## Safety guarantees

* No write path to any router exists in the code.
* The live probe only issues GETs plus an optional login POST; dangerous paths are filtered.
* Firmware stays in RAM; nothing is uploaded anywhere.
* The emulation sandbox has step/time/memory limits and cannot touch the real filesystem.

## If you are unsure

Do not flash. Ask for a second opinion with the exported report attached - it contains the exact
identity of the file, the full matrix, and what the sandbox observed, which is precisely what
someone helping you needs to know.
