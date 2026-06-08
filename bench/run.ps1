<#
.SYNOPSIS
  Face-to-face parity + benchmark of GhidraSharp against pyghidra.

.DESCRIPTION
  Extracts a canonical dump of every bridged RPC twice -- once through the
  GhidraSharp bridge, once through pyghidra in-process -- then diffs them and
  writes bench/REPORT.md. Exits non-zero on any mismatch.

  Requires env GHIDRA_INSTALL_DIR and JAVA_HOME, plus `pyghidra` installed.

.EXAMPLE
  pwsh bench/run.ps1 D:\path\to\PROJECT.gpr
#>
param([Parameter(Mandatory = $true)][string]$Project)

$ErrorActionPreference = "Stop"

foreach ($v in "GHIDRA_INSTALL_DIR", "JAVA_HOME") {
    if (-not (Test-Path "Env:$v")) { throw "set $v before running" }
}

$out = "bench/out"

# 1) make sure the server launch argfile is current
Push-Location server
try { & .\gradlew.bat writeServerArgs -q --console=plain } finally { Pop-Location }

# 2) bridge side (auto-spawns the server)
dotnet run --project bench/GhidraSharp.Parity -c Release -- $Project "$out/cs"

# 3) pyghidra baseline
python bench/pyghidra_extract.py $Project "$out/py"

# 4) compare -> REPORT.md (non-zero exit on mismatch)
python bench/compare.py $out
exit $LASTEXITCODE
