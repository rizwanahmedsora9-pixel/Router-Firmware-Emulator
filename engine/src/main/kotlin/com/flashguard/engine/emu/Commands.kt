package com.flashguard.engine.emu

import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Text

/**
 * The command table of the sandboxed shell.
 *
 * Design rule: anything that *changes state on a real router* is simulated and recorded rather
 * than performed. Anything that could only be answered by real silicon (mtd writes, GPIO, PHY
 * registers, wireless calibration) is recorded as a "hardware touch" and reported to the user.
 */
object Commands {

    fun run(
        name: String,
        argv: List<String>,
        stdin: String,
        shell: SimShell,
        ctx: Any?,
    ): Pair<String, Int> {
        val args = argv.drop(1)
        return when (name) {
            "echo" -> echo(args)
            "printf" -> printf(args)
            "true", ":", ":" -> "" to 0
            "false" -> "" to 1
            "exit" -> return "" to 0
            "return" -> "" to 0
            "break", "continue" -> "" to 0
            "read" -> readCmd(args, stdin, shell)
            "export", "readonly", "typeset" -> export(args, shell)
            "unset" -> {
                args.forEach { shell.variables.remove(it) }
                "" to 0
            }
            "set" -> if (args.isEmpty()) shell.variables.entries.joinToString("\n") { "${it.key}='${it.value}'" } to 0 else "" to 0
            "local" -> {
                args.forEach { a ->
                    val (k, v) = splitAssign(a)
                    shell.setVar(k, v ?: "", local = true)
                }
                "" to 0
            }
            "source", "." -> {
                val path = args.firstOrNull() ?: ""
                val r = shell.runScript(resolve(path, shell), depth = 1)
                r.output to r.exitCode
            }
            "test", "[" -> testCmd(args, shell)
            "cat" -> catCmd(args, stdin, shell)
            "head" -> stdinOrFile(args, stdin, shell) { text -> text.lineSequence().take(10).joinToString("\n") }
            "tail" -> stdinOrFile(args, stdin, shell) { text -> text.lineSequence().toList().takeLast(10).joinToString("\n") }
            "wc" -> {
                val text = fileOrStdin(args, stdin, shell)
                val lines = text.count { it == '\n' }
                val words = text.split(Regex("\\s+")).filter { it.isNotEmpty() }.size
                "  $lines  $words  ${text.length}" to 0
            }
            "grep", "egrep" -> grep(args, stdin, shell)
            "sed" -> sed(args, stdin, shell)
            "awk" -> awk(args, stdin, shell)
            "cut" -> cut(args, stdin, shell)
            "tr" -> {
                val text = fileOrStdin(args, stdin, shell)
                if (args.size >= 2) text.replace(args[0].firstOrNull() ?: ' ', args[1].firstOrNull() ?: ' ') to 0 else text to 0
            }
            "sort" -> fileOrStdin(args, stdin, shell).lines().sorted().joinToString("\n") to 0
            "uniq" -> fileOrStdin(args, stdin, shell).lines().distinct().joinToString("\n") to 0
            "seq" -> {
                val n = args.firstOrNull()?.toIntOrNull() ?: 0
                (1..n).joinToString("\n") to 0
            }
            "expr" -> {
                val nums = args.filter { it.toLongOrNull() != null }.map { it.toLong() }
                val op = args.firstOrNull { it == "+" || it == "-" || it == "*" || it == "/" }
                val v = if (nums.size >= 2 && op != null) when (op) {
                    "+" -> nums[0] + nums[1]
                    "-" -> nums[0] - nums[1]
                    "*" -> nums[0] * nums[1]
                    "/" -> if (nums[1] != 0L) nums[0] / nums[1] else 0
                    else -> 0
                } else 0
                v.toString() to 0
            }
            "basename" -> Text.baseName(args.firstOrNull() ?: "") to 0
            "dirname" -> Text.dirName(args.firstOrNull() ?: "") to 0
            "which", "command", "type" -> (args.firstOrNull() ?: "") to (if (args.isEmpty()) 1 else 0)
            "env", "printenv" -> shell.variables.entries.joinToString("\n") { "${it.key}=${it.value}" } to 0
            "cd" -> "" to 0
            "pwd" -> "/" to 0
            "mkdir" -> {
                var vfs = vfs(shell)
                args.filterNot { it.startsWith("-") }.forEach { vfs.mkdirs(resolve(it, shell)) }
                "" to 0
            }
            "rmdir" -> {
                args.forEach { vfs(shell).delete(resolve(it, shell)) }
                "" to 0
            }
            "rm" -> {
                args.filterNot { it.startsWith("-") }.forEach {
                    val p = resolve(it, shell)
                    vfs(shell).delete(p)
                    shell.logLine("[fs] removed $p")
                }
                "" to 0
            }
            "cp", "mv" -> {
                val ops = args.filterNot { it.startsWith("-") }
                if (ops.size >= 2) {
                    val src = resolve(ops[0], shell)
                    val dst = resolve(ops[1], shell)
                    val content = vfs(shell).read(src)
                    if (content != null) {
                        vfs(shell).addFile(dst, content, source = "emulated $name")
                    } else if (vfs(shell).isDir(src)) {
                        vfs(shell).mkdirs(dst)
                    }
                    if (name == "mv") vfs(shell).delete(src)
                }
                "" to 0
            }
            "ln" -> {
                val ops = args.filterNot { it.startsWith("-") }
                if (ops.size >= 2) {
                    val target = ops[0]
                    val linkPath = resolve(ops[1], shell)
                    vfs(shell).addFile(linkPath, null, 0, 0b111101101, target, "emulated symlink")
                }
                "" to 0
            }
            "touch" -> {
                val p = resolve(args.lastOrNull() ?: "", shell)
                if (!vfs(shell).exists(p)) vfs(shell).write(p, ByteArray(0))
                "" to 0
            }
            "chmod" -> "" to 0
            "chown", "chgrp" -> "" to 0
            "ls" -> ls(args, shell)
            "find" -> find(args, shell)
            "du" -> (args.lastOrNull()?.let { resolve(it, shell) } ?: "/").let { path ->
                val total = vfs(shell).list(path).sumOf { it.size }
                "$total\t$path" to 0
            }
            "df" -> {
                val used = vfs(shell).storedBytes
                "Filesystem      Size  Used Avail Use%\n/dev/root       ${used / 1024}K ${used / 1024}K     0  100%  /" to 0
            }
            "mount" -> {
                if (args.isNotEmpty()) shell.logLine("[mount] simulated: ${args.joinToString(" ")}")
                (if (args.isEmpty()) "rootfs on / type rootfs (rw)\n/dev/root on /rom type squashfs (ro)" else "") to 0
            }
            "umount" -> "" to 0
            "sync", "sleep", "usleep" -> "" to 0
            "insmod", "modprobe", "rmmod", "lsmod" -> module(args, name, shell)
            "ip" -> ip(args, shell)
            "ifconfig" -> ifconfig(args, shell)
            "brctl" -> {
                if (args.size >= 2 && args[0] == "addbr") {
                    shell.interfaces[args[1]] = "bridge (simulated)"
                    shell.logLine("[net] bridge ${args[1]} created")
                }
                "" to 0
            }
            "vconfig", "vlan", "switch", "swconfig", "ethtool", "mii-tool" -> {
                if (args.isNotEmpty()) shell.logLine("[net/$name] ${args.joinToString(" ")}")
                "" to 0
            }
            "iwconfig", "iw", "wlan", "wifi", "hostapd", "wpa_supplicant", "wpa_cli" -> wireless(args, name, shell)
            "route", "iproute" -> {
                if (args.isNotEmpty()) shell.routes.add(args.joinToString(" "))
                "" to 0
            }
            "iptables", "ip6tables", "ebtables", "nft", "ipset" -> {
                if (args.isNotEmpty()) {
                    shell.firewallRules.add("$name ${args.joinToString(" ")}")
                    if (shell.firewallRules.size > 500) shell.firewallRules.removeAt(0)
                }
                "" to 0
            }
            "nvram" -> nvram(args, shell)
            "uci" -> uci(args, shell)
            "httpd", "uhttpd", "lighttpd", "nginx", "mini_httpd", "boa", "thttpd", "goahead", "webs" -> httpd(args, name, shell)
            "telnetd", "dropbear", "sshd", "dnsmasq", "dhcpd", "udhcpd", "odhcpd", "crond", "ntpd", "syslogd", "logd", "klogd",
            "procd", "ubusd", "ubus", "netifd", "igmpproxy", "upnpd", "miniupnpd", "radvd", "smbd", "nmbd", "ftpd", "vsftpd",
            "openvpn", "pppd", "xl2tpd", "scdp", "racoon", "miniupnpd" ->
                daemon(args, name, shell)
            "start-stop-daemon", "service", "invoke-rc.d" -> startStopDaemon(args, shell)
            "start", "stop", "restart", "reload", "enable", "disable", "boot", "shutdown" -> rcAction(name, args, shell)
            "kill", "killall", "pidof", "pgrep", "ps", "top", "uptime", "free", "cat_proc" -> proc(args, name, shell)
            "date" -> "Thu Jan  1 00:00:00 UTC 1970" to 0
            "logger", "logread", "dmesg" -> {
                if (args.isNotEmpty()) shell.logLine("[syslog] ${args.joinToString(" ")}")
                (shell.log.takeLast(40).joinToString("\n")) to 0
            }
            "reboot", "halt", "poweroff", "reset" -> {
                shell.logLine("[system] $name requested (simulated - nothing was rebooted)")
                "" to 0
            }
            "mtd", "ubiformat", "nandwrite", "nanddump", "flash_erase", "flashcp", "mtd_debug", "fw_setenv", "fw_printenv" -> {
                shell.noteHardwareTouch("$name ${args.joinToString(" ")}".trim())
                "" to 0
            }
            "gpio", "i2cget", "i2cset", "spidev", "devmem", "ledctl", "phy", "switch_cli", "wrp", "wlctl", "wl" -> {
                shell.noteHardwareTouch("$name ${args.joinToString(" ")}".trim())
                "" to 0
            }
            "wget", "curl", "tftp", "fetch", "ftpget", "ping", "traceroute", "nc", "netcat", "ssh", "scp", "telnet" -> {
                shell.noteHardwareTouch("network client not executed: $name")
                "" to 0
            }
            "sysupgrade", "firstboot", "jffs2reset", "hotplug", "ubus_call" -> {
                shell.logLine("[upgrade] $name ${args.joinToString(" ")} (recorded, not performed)")
                "" to 0
            }
            "tar", "gzip", "gunzip", "unzip", "bzip2", "xz", "lzma" -> {
                shell.logLine("[archive] $name ${args.joinToString(" ")} (simulated)")
                "" to 0
            }
            "openssl", "dropbearkey", "passwd", "chpasswd", "cryptpw", "mkpasswd" -> {
                shell.logLine("[crypto] $name (simulated)")
                "" to 0
            }
            "hostname" -> {
                if (args.isNotEmpty()) shell.variables["HOSTNAME"] = args[0]
                (shell.variables["HOSTNAME"] ?: "Router") to 0
            }
            "id", "whoami" -> "root" to 0
            "uname" -> {
                val arch = shell.facts().arch ?: "unknown"
                when {
                    args.contains("-a") -> "Linux Router 4.14.0 #1 SMP $arch GNU/Linux" to 0
                    args.contains("-m") -> arch to 0
                    else -> "Linux" to 0
                }
            }
            "lock", "mkfifo", "mknod", "chroot", "nohup", "setsid" -> "" to 0
            "busybox" -> if (args.isNotEmpty()) run(args[0], argv.drop(1).let { listOf(it[0]) + it.drop(1) }, stdin, shell, ctx) else "" to 0
            "ipcalc.sh", "netmsg", "libc", "ldd" -> "" to 0
            else -> {
                shell.noteUnsupported(name)
                "" to 127
            }
        }
    }

    private fun vfs(shell: SimShell): VirtualFs = shellVfs(shell)

    // SimShell owns the VFS; keep the accessor in one place.
    private fun shellVfs(shell: SimShell): VirtualFs = SimShellAccess.vfs(shell)

    private fun resolve(path: String, shell: SimShell): String =
        if (path.startsWith("/")) Text.normPath(path) else Text.normPath("/" + path)

    private fun splitAssign(arg: String): Pair<String, String?> {
        val eq = arg.indexOf('=')
        return if (eq > 0) arg.substring(0, eq) to arg.substring(eq + 1) else arg to null
    }

    private fun echo(args: List<String>): Pair<String, Int> {
        val newline = args.none { it == "-n" }
        val interpret = args.any { it == "-e" }
        var text = args.filterNot { it == "-n" || it == "-e" || it == "-E" }.joinToString(" ")
        if (interpret) {
            text = text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
        }
        return (if (newline) "$text\n" else text) to 0
    }

    private fun printf(args: List<String>): Pair<String, Int> {
        if (args.isEmpty()) return "" to 0
        val fmt = args[0]
        val rest = args.drop(1)
        var idx = 0
        val sb = StringBuilder()
        var i = 0
        while (i < fmt.length) {
            val c = fmt[i]
            if (c == '\\' && i + 1 < fmt.length) {
                sb.append(
                    when (fmt[i + 1]) {
                        'n' -> "\n"; 't' -> "\t"; 'r' -> "\r"; else -> fmt[i + 1].toString()
                    }
                )
                i += 2
                continue
            }
            if (c == '%' && i + 1 < fmt.length) {
                val spec = fmt[i + 1]
                if (spec == 's' || spec == 'd' || spec == 'x') {
                    sb.append(rest.getOrNull(idx++) ?: "")
                    i += 2
                    continue
                }
                if (spec == '%') {
                    sb.append('%')
                    i += 2
                    continue
                }
            }
            sb.append(c)
            i++
        }
        return sb.toString() to 0
    }

    private fun readCmd(args: List<String>, stdin: String, shell: SimShell): Pair<String, Int> {
        val name = args.firstOrNull { !it.startsWith("-") } ?: "REPLY"
        val value = stdin.lineSequence().firstOrNull()?.trim() ?: ""
        shell.setVar(name, value)
        return "" to 0
    }

    private fun export(args: List<String>, shell: SimShell): Pair<String, Int> {
        for (a in args) {
            val (k, v) = splitAssign(a)
            if (v != null) shell.variables[k] = v
        }
        return "" to 0
    }

    private fun testCmd(argsIn: List<String>, shell: SimShell): Pair<String, Int> {
        var args = argsIn.filter { it != "]" }
        if (args.isEmpty()) return "" to 1
        var negate = false
        if (args.first() == "!") {
            negate = true
            args = args.drop(1)
        }
        val result: Boolean = when {
            args.size >= 2 && (args[0] == "-f" || args[0] == "-e" || args[0] == "-d" || args[0] == "-x" || args[0] == "-r" || args[0] == "-s" || args[0] == "-L") -> {
                val path = resolve(args[1], shell)
                when (args[0]) {
                    "-f" -> shellVfs(shell).isFile(path)
                    "-d" -> shellVfs(shell).isDir(path)
                    "-e" -> shellVfs(shell).exists(path)
                    "-L" -> shellVfs(shell).get(path)?.isSymlink == true
                    "-s" -> (shellVfs(shell).get(path)?.size ?: 0) > 0
                    else -> shellVfs(shell).exists(path)
                }
            }
            args.size >= 2 && args[0] == "-z" -> args[1].isEmpty()
            args.size >= 2 && args[0] == "-n" -> args[1].isNotEmpty()
            args.size >= 3 && (args[1] == "=" || args[1] == "==") -> args[0] == args[2]
            args.size >= 3 && args[1] == "!=" -> args[0] != args[2]
            args.size >= 3 && args[1] == "-eq" -> args[0].toLongOrNull() == args[2].toLongOrNull()
            args.size >= 3 && args[1] == "-ne" -> args[0].toLongOrNull() != args[2].toLongOrNull()
            args.size >= 3 && args[1] == "-gt" -> (args[0].toLongOrNull() ?: 0) > (args[2].toLongOrNull() ?: 0)
            args.size >= 3 && args[1] == "-lt" -> (args[0].toLongOrNull() ?: 0) < (args[2].toLongOrNull() ?: 0)
            args.size >= 3 && args[1] == "-ge" -> (args[0].toLongOrNull() ?: 0) >= (args[2].toLongOrNull() ?: 0)
            args.size >= 3 && args[1] == "-le" -> (args[0].toLongOrNull() ?: 0) <= (args[2].toLongOrNull() ?: 0)
            args.size == 1 -> args[0].isNotEmpty()
            else -> false
        }
        val ok = if (negate) !result else result
        return "" to if (ok) 0 else 1
    }

    private fun fileOrStdin(args: List<String>, stdin: String, shell: SimShell): String {
        val file = args.firstOrNull { !it.startsWith("-") }
        if (file != null) {
            val content = shellVfs(shell).readText(resolve(file, shell), 512 * 1024)
            if (content != null) return content
        }
        return stdin
    }

    private inline fun stdinOrFile(args: List<String>, stdin: String, shell: SimShell, transform: (String) -> String): Pair<String, Int> =
        transform(fileOrStdin(args, stdin, shell)) to 0

    private fun catCmd(args: List<String>, stdin: String, shell: SimShell): Pair<String, Int> {
        if (args.isEmpty()) return stdin to 0
        val sb = StringBuilder()
        for (a in args.filterNot { it.startsWith("-") }) {
            val path = resolve(a, shell)
            val entry = shellVfs(shell).get(path)
            when {
                entry == null -> return "cat: $a: No such file or directory" to 1
                entry.isDir -> sb.append("cat: $a: Is a directory\n")
                entry.content != null -> sb.append(String(entry.content!!, Charsets.UTF_8))
                else -> sb.append("[binary/omitted ${entry.size} bytes: ${Text.baseName(path)}]\n")
            }
        }
        return sb.toString() to 0
    }

    private fun grep(args: List<String>, stdin: String, shell: SimShell): Pair<String, Int> {
        val flags = args.filter { it.startsWith("-") }.joinToString("")
        val rest = args.filterNot { it.startsWith("-") }
        if (rest.isEmpty()) return "" to 1
        val pattern = rest[0]
        val files = rest.drop(1)
        val regex = try {
            if (flags.contains("i")) Regex(pattern, RegexOption.IGNORE_CASE) else Regex(pattern)
        } catch (t: Throwable) {
            Regex(Regex.escape(pattern))
        }
        val source = if (files.isEmpty()) stdin else files.joinToString("\n") { shellVfs(shell).readText(resolve(it, shell), 256 * 1024) ?: "" }
        val matches = source.lineSequence().filter { regex.containsMatchIn(it) }.toList()
        if (flags.contains("q")) return "" to (if (matches.isNotEmpty()) 0 else 1)
        if (flags.contains("c")) return matches.size.toString() to 0
        return matches.joinToString("\n") to (if (matches.isNotEmpty()) 0 else 1)
    }

    private fun sed(args: List<String>, stdin: String, shell: SimShell): Pair<String, Int> {
        val script = args.firstOrNull { it.startsWith("s") || it.startsWith("/") } ?: return stdin to 0
        val text = fileOrStdin(args.filter { !it.startsWith("-") }.drop(1), stdin, shell)
        if (script.startsWith("s")) {
            val parts = script.split(script.getOrElse(1) { '/' })
            if (parts.size >= 3) {
                val regex = try {
                    Regex(parts[1])
                } catch (t: Throwable) {
                    Regex(Regex.escape(parts[1]))
                }
                return regex.replace(text, parts[2]) to 0
            }
        }
        return text to 0
    }

    private fun awk(args: List<String>, stdin: String, shell: SimShell): Pair<String, Int> {
        val script = args.firstOrNull() ?: return "" to 0
        val fieldSep = args.firstOrNull { it.startsWith("-F") }?.removePrefix("-F") ?: " "
        val text = fileOrStdin(args.drop(1), stdin, shell)
        val printMatch = Regex("""print\s+\$(\d+)""").find(script)
        val sb = StringBuilder()
        for (line in text.lineSequence()) {
            if (script.contains("BEGIN") && !script.contains("print \$")) continue
            val fields = line.split(fieldSep.takeIf { it.isNotBlank() } ?: " ").filter { it.isNotEmpty() }
            if (printMatch != null) {
                val idx = printMatch.groupValues[1].toInt() - 1
                sb.append(fields.getOrElse(idx) { "" }).append('\n')
            } else if (script.contains("print")) {
                sb.append(line).append('\n')
            }
        }
        return sb.toString() to 0
    }

    private fun cut(args: List<String>, stdin: String, shell: SimShell): Pair<String, Int> {
        val delim = args.firstOrNull { it.startsWith("-d") }?.removePrefix("-d")?.firstOrNull() ?: '\t'
        val fieldSpec = args.firstOrNull { it.startsWith("-f") }?.removePrefix("-f") ?: "1"
        val fields = fieldSpec.split(',').mapNotNull { it.toIntOrNull()?.minus(1) }.filter { it >= 0 }
        val text = fileOrStdin(args.filterNot { it.startsWith("-") }.drop(0), stdin, shell)
        return text.lineSequence().joinToString("\n") { line ->
            val parts = line.split(delim)
            fields.mapNotNull { parts.getOrNull(it) }.joinToString(delim.toString())
        } to 0
    }

    private fun ls(args: List<String>, shell: SimShell): Pair<String, Int> {
        val targets = args.filterNot { it.startsWith("-") }
        val path = if (targets.isEmpty()) "/" else resolve(targets[0], shell)
        val sb = StringBuilder()
        for (e in shellVfs(shell).list(path)) {
            if (args.any { it == "-l" }) {
                sb.append(e.modeString()).append(' ').append(e.size.toString().padStart(8)).append(' ').append(e.name).append('\n')
            } else {
                sb.append(e.name).append(if (e.isDir) "/" else "").append("  ")
            }
        }
        return sb.toString().trimEnd() to 0
    }

    private fun find(args: List<String>, shell: SimShell): Pair<String, Int> {
        val start = args.firstOrNull { !it.startsWith("-") }?.let { resolve(it, shell) } ?: "/"
        val nameIdx = args.indexOf("-name")
        val nameFilter = if (nameIdx >= 0) args.getOrNull(nameIdx + 1) else null
        val entries = shellVfs(shell).allEntries().filter { it.path.startsWith(start) }
        val filtered = if (nameFilter != null) {
            val regex = Regex(Regex.escape(nameFilter).replace("\\*", ".*").replace("\\?", "."))
            entries.filter { regex.matches(Text.baseName(it.path)) }
        } else entries
        return filtered.take(200).joinToString("\n") { it.path } to 0
    }

    private fun module(args: List<String>, name: String, shell: SimShell): Pair<String, Int> {
        return when (name) {
            "lsmod" -> shell.modulesLoaded.joinToString("\n") { "$it 0 0" } to 0
            "rmmod" -> {
                args.forEach { shell.modulesLoaded.remove(it.removeSuffix(".ko")) }
                "" to 0
            }
            else -> {
                val mod = args.lastOrNull()?.removeSuffix(".ko")
                if (mod != null && !shell.modulesLoaded.contains(mod)) {
                    shell.modulesLoaded.add(mod)
                    shell.logLine("[kernel] module loaded: $mod")
                }
                "" to 0
            }
        }
    }

    private fun ip(args: List<String>, shell: SimShell): Pair<String, Int> {
        val sb = StringBuilder()
        when (args.firstOrNull()) {
            "addr", "a", "address" -> {
                if (args.size >= 4 && args.contains("add")) {
                    val iface = args.getOrNull(args.indexOf("add") + 2) ?: args.last()
                    val addr = args.getOrNull(args.indexOf("add") + 1) ?: ""
                    shell.interfaces[iface] = addr
                    shell.logLine("[net] $iface = $addr")
                } else {
                    for ((k, v) in shell.interfaces) sb.append("2: $k    inet $v\n")
                }
            }
            "link", "l" -> {
                if (args.size >= 4 && args.contains("set")) {
                    val iface = args.getOrNull(args.indexOf("set") + 1) ?: ""
                    val state = if (args.contains("up")) "up" else "down"
                    shell.interfaces.putIfAbsent(iface, "no-address")
                    shell.logLine("[net] $iface $state")
                } else {
                    for (k in shell.interfaces.keys) sb.append("2: $k: <BROADCAST,MULTICAST,UP> mtu 1500\n")
                }
            }
            "route", "r" -> {
                if (args.size >= 2) shell.routes.add(args.joinToString(" "))
                shell.routes.joinToString("\n").let { sb.append(it) }
            }
            else -> {}
        }
        return sb.toString() to 0
    }

    private fun ifconfig(args: List<String>, shell: SimShell): Pair<String, Int> {
        if (args.isEmpty()) {
            return shell.interfaces.entries.joinToString("\n") { (k, v) -> "$k  inet addr:$v  Mask:255.255.255.0" } to 0
        }
        val iface = args[0]
        if (args.size >= 2) {
            val addr = args[1]
            if (addr == "up" || addr == "down") {
                shell.interfaces.putIfAbsent(iface, "no-address")
            } else {
                shell.interfaces[iface] = addr
            }
            shell.logLine("[net] ifconfig $iface ${args.drop(1).joinToString(" ")}")
        }
        return "" to 0
    }

    private fun wireless(args: List<String>, name: String, shell: SimShell): Pair<String, Int> {
        if (args.isNotEmpty()) shell.logLine("[wifi] $name ${args.joinToString(" ")}")
        val sb = StringBuilder()
        if (name == "iwconfig" && args.isEmpty()) sb.append("wlan0     IEEE 802.11  ESSID:\"simulated\"\n")
        return sb.toString() to 0
    }

    private fun nvram(args: List<String>, shell: SimShell): Pair<String, Int> {
        val store = NvramStore.of(shell)
        return when (args.firstOrNull()) {
            "get" -> (store[args.getOrNull(1) ?: ""] ?: "") to 0
            "set" -> {
                if (args.size >= 3) store[args[1]] = args.drop(2).joinToString(" ")
                "" to 0
            }
            "unset" -> {
                args.drop(1).forEach { store.remove(it) }
                "" to 0
            }
            "show", "getall" -> store.entries.joinToString("\n") { "${it.key}=${it.value}" } to 0
            "commit", "erase", "defaults" -> {
                shell.logLine("[nvram] ${args.joinToString(" ")}")
                "" to 0
            }
            else -> "" to 0
        }
    }

    private fun uci(args: List<String>, shell: SimShell): Pair<String, Int> {
        val store = UciStore.of(shell)
        return when (args.firstOrNull()) {
            "get" -> (store.get(args.getOrNull(1) ?: "") ?: "") to 0
            "set" -> {
                val kv = args.getOrNull(1) ?: ""
                val eq = kv.indexOf('=')
                if (eq > 0) store.set(kv.substring(0, eq), kv.substring(eq + 1))
                "" to 0
            }
            "add", "delete", "commit", "revert", "rename", "add_list", "del_list" -> {
                shell.logLine("[uci] ${args.joinToString(" ")}")
                "" to 0
            }
            "show" -> {
                val prefix = args.getOrNull(1)
                store.entries
                    .filter { prefix == null || it.key.startsWith(prefix) }
                    .joinToString("\n") { "${it.key}='${it.value}'" } to 0
            }
            else -> "" to 0
        }
    }

    private fun httpd(args: List<String>, name: String, shell: SimShell): Pair<String, Int> {
        var port: Int? = when (name) {
            "httpd" -> 80
            "uhttpd" -> 80
            else -> 80
        }
        var docRoot: String? = null
        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "-p", "-P" -> {
                    port = args.getOrNull(i + 1)?.toIntOrNull() ?: port
                    i += 2
                    continue
                }
                "-h", "-H", "-d", "--home" -> {
                    docRoot = args.getOrNull(i + 1)
                    i += 2
                    continue
                }
            }
            i++
        }
        shell.recordService(
            name = name,
            command = "$name ${args.joinToString(" ")}".trim(),
            port = port,
            simulated = true,
            detail = "docroot=${docRoot ?: "(auto)"}",
        )
        return "" to 0
    }

    private fun daemon(args: List<String>, name: String, shell: SimShell): Pair<String, Int> {
        var port: Int? = when (name) {
            "telnetd" -> 23
            "dropbear", "sshd" -> 22
            "dnsmasq", "dhcpd", "udhcpd", "odhcpd" -> 53
            "miniupnpd", "upnpd" -> 5000
            "smbd" -> 445
            "vsftpd", "ftpd" -> 21
            "openvpn" -> 1194
            "ntpd" -> 123
            else -> null
        }
        val idx = args.indexOfFirst { it == "-p" || it == "--port" || it == "-l" || it == "--listen-port" }
        if (idx >= 0) port = args.getOrNull(idx + 1)?.toIntOrNull() ?: port
        shell.recordService(name, "$name ${args.joinToString(" ")}".trim(), port, simulated = true)
        return "" to 0
    }

    private fun startStopDaemon(args: List<String>, shell: SimShell): Pair<String, Int> {
        val execIdx = args.indexOfFirst { it == "--exec" || it == "-x" || it == "--startas" || it == "-S" }
        val target = if (execIdx >= 0) args.getOrNull(execIdx + 1) ?: args.lastOrNull() else args.lastOrNull()
        val pidIdx = args.indexOfFirst { it == "--pidfile" || it == "-p" }
        val pidFile = if (pidIdx >= 0) args.getOrNull(pidIdx + 1) else null
        if (target != null) {
            shell.recordService(
                name = Text.baseName(target.removePrefix("/")),
                command = "start-stop-daemon ${args.joinToString(" ")}",
                port = null,
                simulated = true,
                detail = pidFile?.let { "pidfile $it" } ?: "",
            )
            if (args.contains("--stop") || args.contains("-K")) shell.packagesStopped.add(target)
        }
        return "" to 0
    }

    private fun rcAction(name: String, args: List<String>, shell: SimShell): Pair<String, Int> {
        val target = args.firstOrNull()
        if (target != null) {
            val svc = Text.baseName(target)
            if (name == "start" || name == "restart") {
                shell.recordService(svc, "$name $target", null, simulated = true, detail = "rc action")
            } else {
                shell.packagesStopped.add(svc)
            }
        }
        return "" to 0
    }

    private fun proc(args: List<String>, name: String, shell: SimShell): Pair<String, Int> {
        if (name == "ps") {
            val sb = StringBuilder("  PID USER       VSZ STAT COMMAND\n")
            sb.append("    1 root      1234 S    /sbin/init (emulated)\n")
            shell.services.forEachIndexed { i, s ->
                sb.append("${(100 + i).toString().padStart(5)} root      2345 S    ${s.command}\n")
            }
            return sb.toString() to 0
        }
        if (name == "uptime") return " 00:00:00 up 0 min, load average: 0.00, 0.00, 0.00" to 0
        if (name == "free") return "              total        used        free\nMem:        131072       32768       98304" to 0
        if (name == "pidof" || name == "pgrep") {
            val target = args.firstOrNull() ?: return "" to 1
            val found = shell.services.any { it.name.contains(target) }
            return (if (found) "123" else "") to (if (found) 0 else 1)
        }
        return "" to 0
    }
}

/** Access shim so Commands can reach the VFS owned by SimShell without exposing mutable state broadly. */
object SimShellAccess {
    private val map = HashMap<SimShell, VirtualFs>()

    fun attach(shell: SimShell, vfs: VirtualFs) {
        map[shell] = vfs
    }

    fun vfs(shell: SimShell): VirtualFs = map[shell] ?: throw IllegalStateException("shell has no VFS attached")
}

/** Broadcom-style nvram store, seeded from the image's nvram defaults. */
object NvramStore {
    private val stores = HashMap<SimShell, LinkedHashMap<String, String>>()

    fun of(shell: SimShell): LinkedHashMap<String, String> =
        stores.getOrPut(shell) { LinkedHashMap(shell.facts().nvramDefaults) }
}

/** OpenWrt uci store backed by the config files in /etc/config of the virtual rootfs. */
object UciStore {
    private val stores = HashMap<SimShell, LinkedHashMap<String, String>>()

    fun of(shell: SimShell): LinkedHashMap<String, String> = stores.getOrPut(shell) {
        val map = LinkedHashMap<String, String>()
        val vfs = SimShellAccess.vfs(shell)
        for (cfg in vfs.allFiles().filter { it.path.startsWith("/etc/config/") }) {
            val section = Text.baseName(cfg.path)
            val text = vfs.readText(cfg.path, 128 * 1024) ?: continue
            var currentSection = "$section.section"
            for (line in text.lineSequence()) {
                val t = line.trim()
                when {
                    t.startsWith("config ") -> {
                        val parts = t.split(" ")
                        val type = parts.getOrNull(1) ?: "config"
                        val name = parts.getOrNull(2)?.trim('\'') ?: "@$type"
                        currentSection = "$section.$name"
                        map["$currentSection"] = type
                    }
                    t.startsWith("option ") -> {
                        val parts = t.removePrefix("option ").split(" ", limit = 2)
                        if (parts.size == 2) map["$section.${currentSection.substringAfter('.')}.${parts[0]}"] = parts[1].trim('\'')
                    }
                }
            }
        }
        map
    }
}
