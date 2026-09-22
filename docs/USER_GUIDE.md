# FlashGuard - user guide

## What this app is for

FlashGuard exists to stop a bad firmware flash from bricking a router. You give it a firmware
file; it unpacks and emulates that file on the phone, compares it against the exact router model
you selected, and tells you - before you touch the real device - whether the image is compatible,
what it boots, which services it starts and whether anything about it is dangerous.

## Step by step

### 1. Open the app and unlock it
The first screen is a local app lock (default `admin` / `admin`). It is not an account and nothing
is sent anywhere: it just keeps a casual bystander out of your firmware files. You can change the
user/password in the app or skip the lock entirely; the choice is remembered.

### 2. Tell it which router you own
Tab **My router** -> *Choose my router model*. Pick the exact model **and revision**: an Archer C6
**v2** and a C6 **v3** are different hardware. If your device is not in the list, pick the closest
entry with the same SoC/flash layout or use a generic profile, and treat every compatibility row
as needing manual confirmation.

Getting this wrong is the single biggest way to get a false "compatible" answer, because the
comparison is made against this profile.

### 3. Give it the firmware
Tab **Analyze**:

* **Choose firmware file** - any file from storage/Downloads (`.bin`, `.img`, `.trx`, `.chk`,
  `.tar`, `.gz`, `.xz`, `.sqfs`, a sysupgrade tarball, a full flash dump ...). Files up to
  64 MiB are supported (that covers every consumer router image; vendor files are usually
  8-32 MB).
* **Load the built-in demo image** - a synthetic OpenWrt-like image generated inside the app,
  useful for seeing the whole pipeline immediately without hunting for a firmware file. It is
  clearly labelled as a demo and never represents real hardware.

### 4. Read the result

| Colour | Meaning | What to do |
|---|---|---|
| **Green** | Every check that matters passed | Still take a backup; the static test cannot prove radio behaviour |
| **Amber** | Something is unverifiable (static analysis limit) | Verify it manually - check the row's "how to confirm" text |
| **Red** | Hardware-incompatible | **Do not flash this file.** The row names the exact conflict |

If the banner instead says *"Could not verify this image - nothing inside it could be unpacked"*,
the app could not read anything out of the file: every content-based row is amber and there is no
verdict about your router either way. Check the *"How the file was identified"* section at the top of
the report (it prints the file's first bytes, its entropy and the containers it looked for) and
compare the file against the vendor's own download - the usual causes are a truncated download, a
vendor-encrypted image, a whole-flash dump, or a file that is not firmware at all.

Rows worth understanding:

* **CPU architecture** - an image for `mipsel` will not run on a `mips`/ARM board. Red.
* **Flash size** - uncompressed rootfs bigger than your flash: the write fails part-way. Red.
* **Flash type** - NAND/UBI image on a NOR device (or the reverse): the bootloader will not find a
  kernel. Red.
* **Bootloader format** - CFE (Broadcom) devices need CFE-format images; U-Boot devices need
  uImage/FIT/sysupgrade images. Red when they disagree.
* **Vendor signature** - locked devices refuse unsigned images. Red.
* **Wi-Fi** - drivers present in the image for chips your device does not have: the radio will not
  come up after flashing. Red. (Amber, not red, when the image could not be unpacked: the app has no
  driver list to compare, and it will say so instead of guessing.)
* **Whole-flash dump** - a full flash image includes the bootloader; writing it is the classic
  unrecoverable brick. Red when the file really is a whole-flash image; for a raw blob of another
  size the row stays amber rather than pretending to know what the file is.
* **Static boot test** - how far the sandbox got: header, kernel, rootfs, init scripts, services,
  web UI. If it does not reach a running userspace, treat the image as unproven.
* **Static analysis coverage** - how much of the file the engine could actually read. If it says
  "header bytes + size only", none of the content-based rows carry evidence - see the note above.

### 5. Preview the firmware's own web files (static, read-only)
Tab **Preview** -> *Start static preview server*. FlashGuard serves the firmware's own `www/`
files byte-for-byte from a loopback-only server inside the app and shows them in a WebView: the
image's own pages, exactly as stored - same theme, same fonts, same menus, nothing added. There
is no login step (a static preview cannot authenticate, and many stock firmwares use a browser
password popup rather than an HTML form anyway). Pages that need the router's own programs show
an honest notice instead of invented content, and the file index lists only what the image
actually ships. If a page looks broken here, that is the truth about the stored template - the
app will not fake the missing live data. Nothing leaves the phone; the server only listens on
`127.0.0.1`.

### 6. Test the router you already have
Tab **Live test**: enter the router's LAN IP (e.g. `192.168.1.1`). FlashGuard performs a
**read-only** check: it fetches the home page a few times to measure stability and latency,
records the web server banner, detects the login form fields, and (optionally) tries the
documented factory-default credentials. It never calls reboot/reset/upgrade/flash endpoints -
those are blocked by a filter, and the check is GET-only apart from the login POST.

Use it before flashing (baseline: is the router healthy?) and after flashing (did it come back up
with the expected features?).

### 7. Export the evidence
Tab **Report** -> toggle Markdown/JSON, then **Copy report to clipboard**, **Share / save report**
(or the same buttons in the report viewer). The Markdown report is meant to be pasted into a forum
post or a support ticket; the JSON is meant for tooling. Both contain the image identity (including
SHA-256), the full compatibility matrix, the boot chain evidence, the emulated web-UI inventory,
security findings and the recommended next steps - including the recovery procedure for your model.

### 8. Send a full diagnostics bundle (report + all logs + watchdog)
When you want to report a firmware result to the developer, open
**Full diagnostics: report + logs + watchdog (copyable)** on the Report tab (or the report viewer's
equivalent button). One screen, one **Copy all** button, and you get a single text block with:

- the safety check report: verdict, risk score, all hardware-matrix rows, all findings, next steps;
- the complete emulated boot chain and the full boot log (every stage detail and note);
- services, interfaces, sandbox files, and every command the image ran that could not be simulated;
- the whole web UI inventory and the emulated server's request log (each login attempt included);
- every extraction warning and unreadable item (the "could not decode" errors), uncensored;
- the **watchdog** (Live test) results in full: reachability, auth scheme, credential attempts,
  every page checked with status/size/latency, all latency samples, p50/p95, the STABLE/UNSTABLE
  verdict, notes and the complete request trace;
- the app run log: every event, warning and error (with stack traces) since the app started, plus
  the crash of the previous run if the app died.

Paste that block into a chat, issue or email - it is self-contained, so nothing else is needed.

## Flashing checklist (the app cannot do this part for you)

1. Matrix has no red rows, and you understand every amber row.
2. Take a full backup / dump of the current firmware if the model supports it.
3. Know your recovery path: TFTP recovery address, reset-button mode, or serial header.
4. Flash over Ethernet, not Wi-Fi, and do not power off during the write.
5. After the reboot, run the **Live test** again: if the login page does not come back within a
   couple of minutes, go straight to recovery - do not keep retrying the flash.

## Privacy

Firmware analysis happens entirely on the phone. The only network traffic the app ever generates
is the optional live test against the LAN address you type in yourself. No telemetry, no uploads,
no accounts.
