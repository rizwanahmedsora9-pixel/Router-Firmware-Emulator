#!/usr/bin/env bash
# Fast local syntax/logic check of the engine without Gradle, Android SDK or Maven access.
# Usage: tools/localcheck.sh [--run]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-$HOME/.cache/toolchain/jdkpy/jdk4py/java-runtime}"
# kotlinc's launcher script calls `java` from PATH, not just JAVA_HOME.
export PATH="$JAVA_HOME/bin:$PATH"
KOTLINC="${KOTLINC:-$HOME/.cache/npm/node_modules/kotlin-compiler/bin/kotlinc}"
OUT="$ROOT/build-local"
mkdir -p "$OUT"
SRC=$(find "$ROOT/engine/src/main/kotlin" -name '*.kt' ! -name 'XzSupport.kt' | sort)
STUB="$ROOT/tools/localstub/XzSupport.kt"
echo "compiling $(echo "$SRC" | wc -l) engine files (XzSupport replaced by stub)…"
# Remove the previous jar first: a stale jar would silently mask a compile failure.
rm -f "$OUT/engine-local.jar"
# shellcheck disable=SC2086
"$KOTLINC" -nowarn -include-runtime $SRC "$STUB" -d "$OUT/engine-local.jar" 2>&1 | grep -v '^warning:' || true
if ! "$JAVA_HOME/bin/java" -version >/dev/null 2>&1; then echo "no JRE available"; exit 1; fi
if [[ ! -f "$OUT/engine-local.jar" ]]; then echo "COMPILE FAILED"; exit 1; fi
echo "engine-local.jar built: $(du -h "$OUT/engine-local.jar" | cut -f1)"
if [[ "${1:-}" == "--run" ]]; then
  shift
  "$JAVA_HOME/bin/java" -cp "$OUT/engine-local.jar" com.flashguard.engine.SelfTestKt "$@"
fi
