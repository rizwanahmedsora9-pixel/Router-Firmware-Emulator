plugins {
    id("org.jetbrains.kotlin.jvm")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Pure-Java XZ/LZMA decoder: works on Android, no native code needed.
    implementation("org.tukaani:xz:1.9")
}

/**
 * Runs the engine's self-test corpus on a plain JVM (no Android device, no JUnit).
 * CI executes this on every push; it also runs locally with:
 *   ./gradlew :engine:engineSelfTest
 */
tasks.register<JavaExec>("engineSelfTest") {
    group = "verification"
    description = "Runs FlashGuard engine self-tests and prints a report."
    mainClass.set("com.flashguard.engine.SelfTestKt")
    classpath = sourceSets["main"].runtimeClasspath
}
