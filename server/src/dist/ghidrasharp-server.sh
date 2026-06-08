#!/usr/bin/env bash
# Launch GhidraSharpServer with the bundled jars + the Ghidra jars from GHIDRA_INSTALL_DIR.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

: "${GHIDRA_INSTALL_DIR:?GHIDRA_INSTALL_DIR is not set; point it at your Ghidra install, e.g. /opt/ghidra_12.1_PUBLIC}"

sep=':'
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) sep=';' ;; esac

libcp="$(ls "$here"/lib/*.jar | paste -sd"$sep" -)"
ghidracp="$(find "$GHIDRA_INSTALL_DIR/Ghidra" -path '*/lib/*.jar' \
    ! -path '*/Debug/*' ! -name 'guava*' ! -name '*-src.jar' | paste -sd"$sep" -)"

exec java -cp "${libcp}${sep}${ghidracp}" \
    io.github.const24.ghidrasharp.server.GhidraSharpServer "$@"
