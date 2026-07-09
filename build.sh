#!/usr/bin/env bash
# Rebuild the architecture-refactored patch for the exact CGN Pen-testing V5.6.1 JAR.
set -euo pipefail
INPUT_JAR="${1:?Usage: ./build.sh <input.jar> <output.jar>}"
OUTPUT_JAR="${2:?Usage: ./build.sh <input.jar> <output.jar>}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/.build"
rm -rf "$BUILD"
mkdir -p "$BUILD/classes"

# Source JAR is Java 21 (classfile major 65).
find "$ROOT/src" -name "*.java" ! -name "PatchCgn.java" -print0 | xargs -0 javac -encoding UTF-8 -cp "$INPUT_JAR" -d "$BUILD/classes"
javac \
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
  -d "$BUILD/classes" "$ROOT/src/PatchCgn.java"

java \
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
  -cp "$BUILD/classes" PatchCgn \
  "$INPUT_JAR" "$BUILD/classes/burp/CgnEnhancement.class" "$OUTPUT_JAR"

(
  cd "$BUILD/classes"
  find burp -type f -name '*.class' | sort | xargs jar uf "$OUTPUT_JAR"
)

printf 'Built: %s\n' "$OUTPUT_JAR"
sha256sum "$OUTPUT_JAR"
