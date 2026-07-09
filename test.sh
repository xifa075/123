#!/usr/bin/env bash
# Run the deterministic compatibility/integration checks using JDK 21.
set -euo pipefail

INPUT_JAR="${1:?Usage: ./test.sh <patched-output.jar>}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/.test-build"
rm -rf "$BUILD"
mkdir -p "$BUILD/burp"

javac -encoding UTF-8 -cp "$INPUT_JAR" -d "$BUILD" \
  "$ROOT/tests/ReliabilityIntegrationTest.java"

java -Xverify:all -cp "$BUILD:$INPUT_JAR" burp.ReliabilityIntegrationTest

# Worker classes must not carry Swing references. This guards against regressions where a
# background path accidentally reads JCheckBox/JTextField/JTable state again.
for worker in burp.ScanOrchestratorCore burp.request.RequestBuilder; do
  if javap -classpath "$INPUT_JAR" -verbose "$worker" | grep -qE 'javax/swing|javax\.swing'; then
    echo "ERROR: $worker contains a direct Swing dependency" >&2
    exit 1
  fi
done

echo "edt-worker-boundary-ok"
