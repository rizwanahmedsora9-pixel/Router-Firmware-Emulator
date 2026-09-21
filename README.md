# Router-Firmware-Emulator

**FlashGuard** - an Android app that takes *any* router firmware file (vendor `.bin`, `.img`, `.trx`,
`chk`, `.ubi`, tar archives...) and runs it through a **static firmware emulation + safety lab**
*on the phone*:

1. **Identify** the image (routers, format, container, compression).
2. **Statically emulate** it - extract the bootloader-preserving structure, find and *execute* the
   init / shell / web-UI logic in a sandboxed simulated rootfs.
3. **Prove activity** - report that the boot chain got to init and the web UI / login page came up.
4. **Score every feature** the image needs against your exact router model, and mark
   **hardware-incompatible** parts in red before you ever touch the flash chip.

> Full source, docs and CI build are in this repository. See `docs/` for the user guide.
