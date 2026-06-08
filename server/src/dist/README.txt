GhidraSharpServer
=================

A headless gRPC server that runs Ghidra as a library for the
Const24.GhidraSharp .NET client (https://github.com/Const24/GhidraSharp).

Requirements
  - Java (JDK) 21 or later on PATH
  - Ghidra 12.1 installed; set GHIDRA_INSTALL_DIR to point at it

Run (Windows / PowerShell):
  $env:GHIDRA_INSTALL_DIR = "C:\ghidra_12.1_PUBLIC"
  .\ghidrasharp-server.ps1

Run (Linux / macOS):
  export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC
  ./ghidrasharp-server.sh

The server listens on 127.0.0.1:50080 (loopback only; override with the
GHIDRASHARP_PORT environment variable). Connect from .NET:

  using var ghidra = GhidraClient.Connect("http://127.0.0.1:50080");

The bundled jars are GhidraSharp + gRPC/protobuf only; the Ghidra jars are
taken from your own GHIDRA_INSTALL_DIR at launch.
