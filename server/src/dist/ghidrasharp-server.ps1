#Requires -Version 5.1
# Launch GhidraSharpServer with the bundled jars + the Ghidra jars from GHIDRA_INSTALL_DIR.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath

$ghidra = $env:GHIDRA_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($ghidra)) {
    Write-Error 'GHIDRA_INSTALL_DIR is not set. Point it at your Ghidra install, e.g. C:\ghidra_12.1_PUBLIC'
    exit 1
}

$libJars = Get-ChildItem -Path (Join-Path $here 'lib') -Filter *.jar | ForEach-Object FullName
$ghidraJars = Get-ChildItem -Path (Join-Path $ghidra 'Ghidra') -Recurse -Filter *.jar |
    Where-Object {
        $_.FullName -match '[\\/]lib[\\/]' -and
        $_.FullName -notmatch '[\\/]Debug[\\/]' -and
        $_.Name -notlike 'guava*' -and
        $_.Name -notlike '*-src.jar'
    } | ForEach-Object FullName

$cp = ($libJars + $ghidraJars) -join ';'
& java '-cp' $cp 'io.github.const24.ghidrasharp.server.GhidraSharpServer' @args
exit $LASTEXITCODE
