package com.flashguard.engine.emu

import com.flashguard.engine.core.FirmwareFacts
import com.flashguard.engine.core.SimService
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.Text

/**
 * A sandboxed POSIX-ish shell interpreter that runs the *logic* of a firmware's init scripts
 * without executing a single CPU instruction of it.
 *
 * Why: ARM/MIPS binaries can't run on a phone, but ~all of a router's boot decisions are made in
 * shell (or in a shell-called binary whose effect is visible in config). This interpreter executes
 * those scripts against the virtual rootfs, records what they do (network state, modules, services,
 * files), and reports the boot stages the image reaches.
 *
 * It NEVER touches the phone's real filesystem or network and is bounded by [Limits].
 */
class SimShell(
    private val vfs: VirtualFs,
    private val facts: FirmwareFacts,
    private val maxSteps: Int = Limits.MAX_SHELL_STEPS,
    private val deadlineMs: Long = Long.MAX_VALUE,
) {
    data class Result(val output: String, val exitCode: Int)

    val variables = HashMap<String, String>()
    val functions = HashMap<String, String>()
    val localScopes = ArrayList<MutableMap<String, String>>()
    val services = ArrayList<SimService>()
    val interfaces = LinkedHashMap<String, String>()
    val routes = ArrayList<String>()
    val modulesLoaded = ArrayList<String>()
    val filesCreated = ArrayList<String>()
    val unsupported = LinkedHashMap<String, Int>()
    val hardwareTouches = LinkedHashMap<String, Int>()
    val log = ArrayList<String>(512)
    val firewallRules = ArrayList<String>()
    val packagesStopped = ArrayList<String>()

    var steps = 0
        private set
    var timeouts = 0
        private set
    var truncated = false
        private set

    private val startedAt = System.currentTimeMillis()

    init {
        SimShellAccess.attach(this, vfs)
        variables["PATH"] = "/sbin:/bin:/usr/sbin:/usr/bin"
        variables["SHELL"] = "/bin/sh"
        variables["HOME"] = "/root"
        variables["USER"] = "root"
        variables["PS1"] = "# "
        variables["TERM"] = "linux"
        variables["HOSTNAME"] = "Router"
    }

    private val ASSIGN = Regex("^[A-Za-z_][A-Za-z0-9_]*=.*$")

    fun logLine(line: String) {
        if (log.size < 4000) log.add(line)
    }

    private fun budgetExceeded(): Boolean {
        if (steps >= maxSteps) {
            truncated = true
            return true
        }
        if (System.currentTimeMillis() - startedAt > deadlineMs) {
            timeouts++
            truncated = true
            return true
        }
        return false
    }

    // ------------------------------------------------------------------ entry points

    fun runString(script: String, label: String = "inline", depth: Int = 0): Result {
        if (depth > Limits.MAX_CALL_DEPTH) return Result("", 1)
        if (budgetExceeded()) return Result("", 1)
        val ast = try {
            Parser(Lexer(script).tokens()).parseList(emptySet())
        } catch (t: Throwable) {
            // Half-broken vendor scripts are common: log and continue with what parsed.
            logLine("[shell] could not parse $label: ${t.message}")
            return Result("", 1)
        }
        val ctx = Ctx()
        for (node in ast) {
            val r = eval(node, ctx, depth)
            if (r.signal == Signal.EXIT_ALL) break
        }
        return Result(ctx.capture(), 0)
    }

    fun runScript(path: String, depth: Int = 0): Result = runScriptWithArgs(path, emptyList(), depth)

    /**
     * Runs a script from the virtual rootfs, reproducing OpenWrt's rc.common dispatch:
     * `/etc/init.d/uhttpd start` defines the functions in the script and then calls start().
     */
    fun runScriptWithArgs(path: String, args: List<String>, depth: Int = 0): Result {
        val resolved = resolveInVfs(path)
        val text = vfs.readText(resolved, 256 * 1024) ?: return Result("", 127)
        logLine("+ ${Text.truncate(resolved, 80)}${if (args.isNotEmpty()) " " + args.joinToString(" ") else ""}")
        val usesRcCommon = text.lineSequence().firstOrNull()?.contains("rc.common") == true ||
            text.contains("/etc/rc.common")
        val result = runString(text, resolved, depth)
        // rc.common behaviour: dispatch on the action argument (start/stop/restart/...).
        if (args.isNotEmpty()) {
            val action = args[0]
            val fn = functionBodies[action]
            if (fn != null && depth < Limits.MAX_CALL_DEPTH) {
                localScopes.add(HashMap())
                localScopes.last()["1"] = action
                val r = Ctx()
                for (n in fn) eval(n, r, depth + 1)
                localScopes.removeAt(localScopes.size - 1)
                return Result(result.output, r.exitCode)
            }
            if (usesRcCommon && action in listOf("enable", "disable", "enabled", "boot", "start", "stop", "restart", "reload")) {
                // Defined by rc.common itself; nothing to do in the sandbox.
                return result
            }
        } else if (functionBodies.containsKey("start")) {
            // Executed directly (no argument): rc.common defaults to start.
            val fn = functionBodies["start"]!!
            val r = Ctx()
            for (n in fn) eval(n, r, depth + 1)
            return Result(result.output + r.capture(), r.exitCode)
        }
        return result
    }

    /** Absolute or relative path -> a real path inside the virtual rootfs. */
    fun resolveInVfs(path: String): String {
        val candidate = Text.normPath(if (path.startsWith("/")) path else "/$path")
        if (vfs.exists(candidate)) return candidate
        val bare = candidate.trimStart('/')
        if (vfs.exists("/bin/$bare")) return "/bin/$bare"
        if (vfs.exists("/sbin/$bare")) return "/sbin/$bare"
        if (vfs.exists("/usr/bin/$bare")) return "/usr/bin/$bare"
        if (vfs.exists("/usr/sbin/$bare")) return "/usr/sbin/$bare"
        return candidate
    }

    // ------------------------------------------------------------------ AST + evaluation

    enum class Signal { NONE, BREAK, CONTINUE, RETURN, EXIT_ALL }

    class Ctx {
        val sb = StringBuilder()
        var exitCode = 0
        var signal = Signal.NONE
        var returnValue = 0
        var stdin = ""
        var outputCapture: StringBuilder? = null

        fun emit(s: String) {
            outputCapture?.append(s) ?: sb.append(s)
        }

        fun capture(): String = sb.toString()
    }

    private sealed class Node
    private class AndOr(val pipelines: MutableList<Pair<String, Pipeline>> = ArrayList()) : Node()
    private class Pipeline(val commands: MutableList<Node> = ArrayList()) : Node()
    private class Simple(
        val words: MutableList<String>,
        val redirects: MutableList<Redirect> = ArrayList(),
    ) : Node()

    private class Redirect(val fd: Int, val op: String, val target: String)
    private class IfNode(val branches: MutableList<Pair<List<Node>, List<Node>>>, val elseBody: List<Node>?) : Node()
    private class ForNode(val name: String, val words: List<String>, val body: List<Node>) : Node()
    private class WhileNode(val cond: List<Node>, val body: List<Node>) : Node()
    private class CaseNode(val subject: String, val arms: MutableList<Pair<List<String>, List<Node>>>) : Node()
    private class GroupNode(val body: List<Node>) : Node()
    private class FuncDef(val name: String, val body: List<Node>) : Node()

    private val localVars = HashMap<String, String>()

    private fun eval(node: Node, ctx: Ctx, depth: Int): Ctx {
        if (budgetExceeded()) return ctx
        when (node) {
            is AndOr -> {
                var lastExit = 0
                for ((op, pipeline) in node.pipelines) {
                    if (op == "&&" && lastExit != 0) continue
                    if (op == "||" && lastExit == 0) continue
                    eval(pipeline, ctx, depth)
                    lastExit = ctx.exitCode
                    if (ctx.signal == Signal.EXIT_ALL) return ctx
                }
            }
            is Pipeline -> {
                var input = ctx.stdin
                var output = ""
                for ((i, cmd) in node.commands.withIndex()) {
                    if (budgetExceeded()) break
                    val sub = Ctx()
                    sub.stdin = input
                    sub.outputCapture = StringBuilder()
                    steps++
                    eval(cmd, sub, depth)
                    output = sub.outputCapture?.toString() ?: ""
                    ctx.exitCode = 0
                    if (i < node.commands.size - 1) input = output
                }
                if (output.isNotEmpty()) ctx.emit(output)
            }
            is Simple -> runSimple(node, ctx, depth)
            is IfNode -> {
                var handled = false
                for ((cond, body) in node.branches) {
                    val condCtx = Ctx()
                    for (c in cond) eval(c, condCtx, depth)
                    if (condCtx.exitCode == 0) {
                        for (b in body) eval(b, ctx, depth)
                        handled = true
                        break
                    }
                }
                if (!handled && node.elseBody != null) {
                    for (b in node.elseBody) eval(b, ctx, depth)
                }
            }
            is ForNode -> {
                val items = if (node.words.isEmpty()) emptyList() else words(node.words, ctx)
                var iterations = 0
                for (item in items) {
                    if (++iterations > Limits.MAX_LOOP_ITERATIONS) {
                        timeouts++
                        break
                    }
                    variables[node.name] = item
                    for (b in node.body) eval(b, ctx, depth)
                    if (ctx.signal == Signal.BREAK) {
                        ctx.signal = Signal.NONE
                        break
                    }
                    if (ctx.signal == Signal.CONTINUE) ctx.signal = Signal.NONE
                    if (ctx.signal == Signal.EXIT_ALL || budgetExceeded()) break
                }
            }
            is WhileNode -> {
                var iterations = 0
                while (true) {
                    if (++iterations > Limits.MAX_LOOP_ITERATIONS || budgetExceeded()) {
                        timeouts++
                        break
                    }
                    val condCtx = Ctx()
                    for (c in node.cond) eval(c, condCtx, depth)
                    if (condCtx.exitCode != 0) break
                    for (b in node.body) eval(b, ctx, depth)
                    if (ctx.signal == Signal.BREAK) {
                        ctx.signal = Signal.NONE
                        break
                    }
                    if (ctx.signal == Signal.CONTINUE) ctx.signal = Signal.NONE
                    if (ctx.signal == Signal.EXIT_ALL) break
                }
            }
            is CaseNode -> {
                val subject = expand(node.subject, ctx)
                for ((patterns, body) in node.arms) {
                    val hit = patterns.any { p ->
                        val pat = expand(p, ctx)
                        patternMatches(pat, subject)
                    }
                    if (hit) {
                        for (b in body) eval(b, ctx, depth)
                        break
                    }
                }
            }
            is GroupNode -> for (b in node.body) eval(b, ctx, depth)
            is FuncDef -> functionBodies[node.name] = node.body
        }
        return ctx
    }

    private val functionBodies = HashMap<String, List<Node>>()

    private fun patternMatches(pattern: String, subject: String): Boolean {
        val p = pattern.trim('"', '\'')
        if (p == subject) return true
        val regex = Regex(
            "^" + Regex.escape(p).replace("\\*", "\\E.*\\Q").replace("\\?", "\\E.\\Q") + "$"
        )
        return regex.matches(subject)
    }

    private fun runSimple(node: Simple, ctx: Ctx, depth: Int): Ctx {
        var argv = words(node.words, ctx)
        if (argv.isEmpty()) return ctx

        // Variable assignments: NAME=value [NAME2=value ...] [command]
        var assignIdx = 0
        while (assignIdx < argv.size && ASSIGN.matches(argv[assignIdx])) {
            val assign = argv[assignIdx]
            val eq = assign.indexOf('=')
            setVar(assign.substring(0, eq), assign.substring(eq + 1))
            assignIdx++
        }
        if (assignIdx >= argv.size) return ctx // pure assignment, nothing to execute
        if (assignIdx > 0) argv = argv.drop(assignIdx)

        val name = argv[0]

        // Executing a file from the rootfs (e.g. "/etc/init.d/uhttpd start", "./script.sh").
        if (name.startsWith("/") || name.startsWith("./")) {
            val resolved = resolveInVfs(name)
            if (vfs.isFile(resolved)) {
                val r = runScriptWithArgs(resolved, argv.drop(1), depth + 1)
                ctx.exitCode = r.exitCode
                if (r.output.isNotEmpty()) ctx.emit(r.output)
                return ctx
            }
        }

        // function call?
        val fn = functionBodies[name]
        if (fn != null) {
            if (depth >= Limits.MAX_CALL_DEPTH) return ctx
            localScopes.add(HashMap())
            for ((i, value) in argv.drop(1).withIndex()) localScopes.last()[(i + 1).toString()] = value
            localScopes.last()["@"] = argv.drop(1).joinToString(" ")
            localScopes.last()["*"] = argv.drop(1).joinToString(" ")
            localScopes.last()["#"] = argv.drop(1).size.toString()
            val r = Ctx()
            r.stdin = ctx.stdin
            for (n in fn) eval(n, r, depth + 1)
            localScopes.removeAt(localScopes.size - 1)
            ctx.exitCode = r.exitCode
            if (r.outputCapture == null && r.capture().isNotEmpty()) ctx.emit(r.capture())
            return ctx
        }

        val (out, code) = Commands.run(name, argv, ctx.stdin, this, ctx)
        ctx.exitCode = code
        applyRedirects(node, out, ctx)
        return ctx
    }

    private fun applyRedirects(node: Simple, output: String, ctx: Ctx) {
        var text = output
        var consumed = false
        for (r in node.redirects) {
            if (r.op.startsWith(">")) {
                val target = expand(r.target, ctx)
                when (r.op) {
                    ">", "1>" -> vfs.write(target, text.toByteArray(Charsets.UTF_8), 0b110100100)
                    ">>", "1>>" -> vfs.append(target, text)
                    "2>", "2>>" -> Unit // stderr is dropped in the simulator
                }
                filesCreated.add(target)
                consumed = true
            } else if (r.op.startsWith("<")) {
                val target = expand(r.target, ctx)
                text = vfs.readText(target, 65536) ?: ""
            }
        }
        if (text.isNotEmpty() && !consumed) ctx.emit(text)
    }

    fun words(list: List<String>, ctx: Ctx? = null): List<String> =
        list.filter { it.isNotEmpty() }.map { expand(it, ctx) }

    /** Variable, ${var}, $(cmd), and quote handling. */
    fun expand(raw: String, ctx: Ctx?): String {
        val sb = StringBuilder()
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            when {
                c == '$' && i + 1 < raw.length -> {
                    when {
                        raw[i + 1] == '(' && i + 2 < raw.length && raw[i + 2] == '(' -> {
                            val end = matchParen(raw, i + 1)
                            val inner = raw.substring(minOf(i + 3, end), maxOf(i + 3, end - 1))
                            sb.append(evalArithmetic(inner))
                            i = end + 1
                        }
                        raw[i + 1] == '(' -> {
                            val end = matchParen(raw, i + 1)
                            val inner = raw.substring(i + 2, end).trim()
                            val output = if (inner.startsWith("(")) evalArithmetic(inner.trim('(', ')')) else runString(inner, "command substitution", 1).output.trim()
                            sb.append(output)
                            i = end + 1
                        }
                        raw[i + 1] == '{' -> {
                            val end = raw.indexOf('}', i)
                            if (end < 0) {
                                sb.append(c); i++
                            } else {
                                val expr = raw.substring(i + 2, end)
                                sb.append(lookup(expr))
                                i = end + 1
                            }
                        }
                        else -> {
                            var j = i + 1
                            while (j < raw.length && (raw[j].isLetterOrDigit() || raw[j] == '_')) j++
                            val name = raw.substring(i + 1, j)
                            sb.append(lookup(name))
                            i = j
                        }
                    }
                }
                else -> {
                    sb.append(c)
                    i++
                }
            }
        }
        return sb.toString()
    }

    /** Integer arithmetic for arithmetic expansion - variables, + - * / %, parentheses. */
    private fun evalArithmetic(expr: String): String = try {
        Arith(expr, this).evaluate().toString()
    } catch (t: Throwable) {
        "0"
    }

    /** Tiny recursive-descent integer evaluator (methods can reference each other freely). */
    private class Arith(private val expr: String, private val shell: SimShell) {
        private var i = 0

        fun evaluate(): Long = parseSum()

        private fun skipWs() {
            while (i < expr.length && expr[i].isWhitespace()) i++
        }

        private fun peek(): Char? {
            skipWs()
            return if (i < expr.length) expr[i] else null
        }

        private fun parsePrimary(): Long {
            skipWs()
            when (peek()) {
                '(' -> {
                    i++
                    val v = parseSum()
                    if (peek() == ')') i++
                    return v
                }
                '-' -> {
                    i++
                    return -parsePrimary()
                }
                '+' -> {
                    i++
                    return parsePrimary()
                }
                else -> Unit
            }
            val start = i
            while (i < expr.length && (expr[i].isLetterOrDigit() || expr[i] == '_' || expr[i] == '$' || expr[i] == '.')) i++
            var token = expr.substring(start, i).removePrefix("$").trim()
            if (token.isEmpty()) return 0
            token.toLongOrNull()?.let { return it }
            if (token.startsWith("0x", true)) token.substring(2).toLongOrNull(16)?.let { return it }
            return shell.getVar(token).trim().toLongOrNull() ?: 0
        }

        private fun parseProduct(): Long {
            var v = parsePrimary()
            while (true) {
                when (peek()) {
                    '*' -> {
                        i++
                        v *= parsePrimary()
                    }
                    '/' -> {
                        i++
                        val d = parsePrimary()
                        v = if (d == 0L) 0 else v / d
                    }
                    '%' -> {
                        i++
                        val d = parsePrimary()
                        v = if (d == 0L) 0 else v % d
                    }
                    else -> return v
                }
            }
        }

        private fun parseSum(): Long {
            var v = parseProduct()
            while (true) {
                when (peek()) {
                    '+' -> {
                        i++
                        v += parseProduct()
                    }
                    '-' -> {
                        i++
                        v -= parseProduct()
                    }
                    else -> return v
                }
            }
        }
    }

    private fun matchParen(s: String, open: Int): Int {
        var depth = 0
        var i = open
        while (i < s.length) {
            when (s[i]) {
                '(' -> depth++
                ')' -> {
                    depth--
                    if (depth == 0) return i
                }
            }
            i++
        }
        return s.length - 1
    }

    private fun lookup(name: String): String {
        for (i in localScopes.indices.reversed()) {
            localScopes[i][name]?.let { return it }
        }
        localVars[name]?.let { return it }
        variables[name]?.let { return it }
        return when (name) {
            "hostname", "HOST_NAME" -> variables["HOSTNAME"] ?: "Router"
            "seq" -> ""
            else -> ""
        }
    }

    fun setVar(name: String, value: String, local: Boolean = false) {
        if (local) {
            if (localScopes.isNotEmpty()) localScopes.last()[name] = value else localVars[name] = value
        } else {
            variables[name] = value
        }
    }

    fun getVar(name: String): String = lookup(name)

    // ------------------------------------------------------------------ lexer

    private class Lexer(private val src: String) {
        // Tokens: WORD, operators, newline ;, keywords are just words.
        fun tokens(): List<String> {
            val out = ArrayList<String>(src.length / 4)
            var i = 0
            val sb = StringBuilder()
            fun flush() {
                if (sb.isNotEmpty()) {
                    out.add(sb.toString())
                    sb.setLength(0)
                }
            }
            while (i < src.length) {
                val c = src[i]
                when {
                    c == '\\' && i + 1 < src.length && src[i + 1] == '\n' -> i += 2
                    c == '\\' && i + 1 < src.length -> {
                        sb.append(src[i + 1])
                        i += 2
                    }
                    c == '#' && sb.isEmpty() && (out.isEmpty() || out.last() == ";" || out.last() == "\n") -> {
                        while (i < src.length && src[i] != '\n') i++
                    }
                    c == '\'' -> {
                        val end = src.indexOf('\'', i + 1)
                        val stop = if (end < 0) src.length else end
                        sb.append(src, i + 1, stop)
                        i = stop + 1
                    }
                    c == '"' -> {
                        val (content, next) = readDoubleQuoted(src, i)
                        sb.append(content)
                        i = next
                    }
                    c == '$' && i + 1 < src.length && src[i + 1] == '(' -> {
                        val end = matchParenStatic(src, i + 1)
                        sb.append(src, i, end + 1)
                        i = end + 1
                    }
                    c == '\n' -> {
                        flush()
                        out.add("\n")
                        i++
                    }
                    c.isWhitespace() -> {
                        flush()
                        i++
                    }
                    c == ';' || c == '&' || c == '|' -> {
                        flush()
                        val two = if (i + 1 < src.length) src.substring(i, i + 2) else ""
                        if (two == "&&" || two == "||" || two == ">>" || two == ";;" || two == "<&") {
                            out.add(two)
                            i += 2
                        } else {
                            out.add(c.toString())
                            i++
                        }
                    }
                    c == '>' || c == '<' -> {
                        flush()
                        val two = if (i + 1 < src.length) src.substring(i, i + 2) else ""
                        if (two == ">>" ) {
                            out.add(">>"); i += 2
                        } else {
                            out.add(c.toString()); i++
                        }
                    }
                    c == '(' || c == ')' || c == '{' || c == '}' -> {
                        flush()
                        out.add(c.toString())
                        i++
                    }
                    else -> {
                        sb.append(c)
                        i++
                    }
                }
            }
            flush()
            return out
        }

        private fun readDoubleQuoted(s: String, start: Int): Pair<String, Int> {
            val sb = StringBuilder()
            var i = start + 1
            while (i < s.length) {
                val c = s[i]
                if (c == '\\' && i + 1 < s.length) {
                    sb.append(c).append(s[i + 1])
                    i += 2
                    continue
                }
                if (c == '"') return sb.toString() to (i + 1)
                if (c == '$' && i + 1 < s.length && s[i + 1] == '(') {
                    val end = matchParenStatic(s, i + 1)
                    sb.append(s, i, end + 1)
                    i = end + 1
                    continue
                }
                sb.append(c)
                i++
            }
            return sb.toString() to s.length
        }

        private fun matchParenStatic(s: String, open: Int): Int {
            var depth = 0
            var i = open
            while (i < s.length) {
                when (s[i]) {
                    '(' -> depth++
                    ')' -> {
                        depth--
                        if (depth == 0) return i
                    }
                }
                i++
            }
            return s.length - 1
        }
    }

    // ------------------------------------------------------------------ parser

    private class Parser(val t: List<String>) {
        var p = 0
        fun peek(): String? = t.getOrNull(p)
        fun next(): String = t.getOrNull(p++) ?: ""
        fun eof(): Boolean = p >= t.size

        fun parseList(stop: Set<String>): List<Node> {
            val nodes = ArrayList<Node>()
            while (!eof() && peek() !in stop) {
                val tok = peek()
                if (tok == ";" || tok == "\n" || tok == "&") {
                    p++
                    continue
                }
                val node = parseAndOr(stop)
                if (node != null) nodes.add(node) else p++
            }
            return nodes
        }

        private fun parseAndOr(stop: Set<String>): Node? {
            val pipelines = ArrayList<Pair<String, Pipeline>>()
            var op = ""
            while (!eof()) {
                if (peek() in stop) break
                val pl = parsePipeline(stop) ?: break
                pipelines.add(op to pl)
                val nxt = peek()
                if (nxt == "&&" || nxt == "||") {
                    op = next()
                } else break
            }
            return if (pipelines.isEmpty()) null else AndOr(pipelines)
        }

        private fun parsePipeline(stop: Set<String>): Pipeline? {
            val commands = ArrayList<Node>()
            while (!eof()) {
                if (peek() in stop) break
                val cmd = parseCommand(stop) ?: break
                commands.add(cmd)
                if (peek() == "|") {
                    next()
                } else break
            }
            return if (commands.isEmpty()) null else Pipeline(commands)
        }

        private fun parseCommand(stop: Set<String>): Node? {
            val tok = peek() ?: return null
            return when (tok) {
                "if" -> parseIf(stop)
                "for" -> parseFor(stop)
                "while" -> parseWhile(stop)
                "case" -> parseCase(stop)
                "{" -> {
                    next()
                    val body = parseList(setOf("}"))
                    if (peek() == "}") next()
                    GroupNode(body)
                }
                "(" -> {
                    next()
                    val body = parseList(setOf(")"))
                    if (peek() == ")") next()
                    GroupNode(body)
                }
                ";" , "\n", "&&", "||", "|", "}" -> null
                else -> {
                    // function definition: name ( ) { ... }
                    if (p + 2 < t.size && t[p + 1] == "(" && t[p + 2] == ")") {
                        val name = next()
                        next(); next()
                        val body = if (peek() == "{") {
                            next()
                            val b = parseList(setOf("}"))
                            if (peek() == "}") next()
                            b
                        } else emptyList()
                        FuncDef(name, body)
                    } else {
                        parseSimple(stop)
                    }
                }
            }
        }

        private fun parseSimple(stop: Set<String>): Node? {
            val words = ArrayList<String>()
            val redirects = ArrayList<Redirect>()
            while (!eof()) {
                val tok = peek()!!
                if (tok in stop || tok == ";" || tok == "\n" || tok == "&" || tok == "&&" || tok == "||" || tok == "|") break
                if (tok == ">" || tok == ">>" || tok == "<" || tok == "2>" || tok == "1>") {
                    val op = next()
                    val target = if (!eof()) next() else ""
                    redirects.add(Redirect(if (op.startsWith("2")) 2 else 1, op, target))
                    continue
                }
                if ((tok == "2" || tok == "1") && (t.getOrNull(p + 1) == ">" || t.getOrNull(p + 1) == ">>")) {
                    val fd = next()
                    val op = next()
                    val target = if (!eof()) next() else ""
                    redirects.add(Redirect(fd.toInt(), "$fd$op", target))
                    continue
                }
                words.add(next())
            }
            return if (words.isEmpty() && redirects.isEmpty()) null else Simple(words, redirects)
        }

        private fun parseIf(stop: Set<String>): Node {
            next() // if
            val branches = ArrayList<Pair<List<Node>, List<Node>>>()
            var cond = parseList(setOf("then"))
            while (true) {
                if (peek() == "then") next()
                val body = parseList(setOf("elif", "else", "fi"))
                branches.add(cond to body)
                when (peek()) {
                    "elif" -> {
                        next()
                        cond = parseList(setOf("then"))
                    }
                    "else" -> {
                        next()
                        val elseBody = parseList(setOf("fi"))
                        if (peek() == "fi") next()
                        return IfNode(branches, elseBody)
                    }
                    else -> {
                        if (peek() == "fi") next()
                        return IfNode(branches, null)
                    }
                }
            }
        }

        private fun parseFor(stop: Set<String>): Node {
            next() // for
            val name = next()
            val words = ArrayList<String>()
            if (peek() == "in") {
                next()
                while (!eof() && peek() != ";" && peek() != "\n" && peek() != "do") {
                    words.add(next())
                }
            }
            while (peek() == ";" || peek() == "\n") next()
            if (peek() == "do") next()
            val body = parseList(setOf("done"))
            if (peek() == "done") next()
            return ForNode(name, words, body)
        }

        private fun parseWhile(stop: Set<String>): Node {
            next()
            val cond = parseList(setOf("do"))
            if (peek() == "do") next()
            val body = parseList(setOf("done"))
            if (peek() == "done") next()
            return WhileNode(cond, body)
        }

        private fun parseCase(stop: Set<String>): Node {
            next() // case
            val subject = if (!eof()) next() else ""
            if (peek() == "in") next()
            val arms = ArrayList<Pair<List<String>, List<Node>>>()
            while (!eof() && peek() != "esac") {
                val patterns = ArrayList<String>()
                while (!eof() && peek() != ")") {
                    val pat = next()
                    if (pat != "|") patterns.add(pat)
                }
                if (peek() == ")") next()
                val body = parseList(setOf(";;", "esac"))
                arms.add(patterns to body)
                if (peek() == ";;") next()
            }
            if (peek() == "esac") next()
            return CaseNode(subject, arms)
        }
    }

    // ------------------------------------------------------------------ introspection for commands

    fun recordService(name: String, command: String, port: Int?, simulated: Boolean, detail: String = "") {
        if (services.none { it.name == name && it.port == port }) {
            services.add(SimService(name, command, port, simulated, detail))
            logLine("service started: $name${port?.let { " on port $it" } ?: ""}")
        }
    }

    fun noteUnsupported(cmd: String) {
        unsupported[cmd] = (unsupported[cmd] ?: 0) + 1
    }

    fun noteHardwareTouch(what: String, count: Int = 1) {
        hardwareTouches[what] = (hardwareTouches[what] ?: 0) + count
        logLine("[hardware] $what (not simulated)")
    }

    fun facts(): FirmwareFacts = facts
}
