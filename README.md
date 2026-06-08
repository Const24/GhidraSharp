# GhidraSharp

A typed **C# client for [Ghidra](https://ghidra-sre.org/)** over a small gRPC bridge.
No Python in the chain.

There is no official or popular C# binding to Ghidra — the community option is
the Python `ghidra_bridge`, and Ghidra's only first-party cross-language wire
protocol (TraceRmi) is debugger-scoped, not the static analysis API. GhidraSharp
fills that gap with a deliberately small, typed surface:

```
  ┌────────────────────┐   gRPC (protobuf)   ┌──────────────────────────────┐
  │ Const24.GhidraSharp │  ───────────────▶   │ GhidraSharpServer (Java)     │
  │ (C# client, net10)  │  ◀───────────────   │ Ghidra-as-library, headless  │
  └────────────────────┘                      └──────────────────────────────┘
```

* **`proto/ghidrasharp.proto`** — the single source of truth for the wire
  contract. Both sides generate from it; nobody hand-writes DTOs.
* **`src/GhidraSharp/`** — the C# client library (NuGet `Const24.GhidraSharp`,
  namespace `Const24.GhidraSharp`). Generates gRPC client stubs from the proto
  at build via `Grpc.Tools`.
* **`src/GhidraSharp.Sample/`** — a console smoke test for the bridge.
* **`server/`** — the Java gRPC server that runs Ghidra as a library and serves
  decompilation / analysis (Gradle build).

## Status

Working bridge. The surface grows one RPC at a time as consumers need it.

* `Ping` — liveness + Ghidra version
* `OpenProgram` — open an analyzed project, or import a binary
* `DecompileFunction` / `DecompileFunctions` (batch, server-streamed) — function → C
* `ListFunctions` — functions (+ callees), built to query client-side with LINQ
* `GetReferencesTo` / `GetReferencesFrom` — cross-references (xrefs)
* `ListSymbols` / `GetSymbolsAt` — symbols by name or address
* `RenameSymbol` — record a finding back onto the program (needs `writable: true`; in-memory unless saved)
* `ReadBytes` — raw program memory (feeds a pure-C# byte/table layer)
* `GetInstructions` — the disassembly listing (mnemonic, operands, bytes)

Architecture-agnostic by construction — it just forwards a Ghidra language id, so
the same code drives any processor Ghidra supports (validated on SH-2A firmware
and an x86-64 PE).

The public C# API exposes only hand-written, documented result types
(`ProgramInfo`, `GhidraFunction`, `Decompilation`, `GhidraReference`, …); the
generated gRPC wire types are internal. Names follow Ghidra's own terms so they
read right to a Ghidra user, with XML docs that also explain each concept to a
.NET developer new to Ghidra. Validated **byte-for-byte against pyghidra across
the whole API** (functions, symbols, decompilation, instructions, xrefs, bytes)
at comparable speed — see the [parity report](bench/REPORT.md) and [bench/](bench/).

## Building the client

```sh
dotnet build GhidraSharp.slnx
```

## Why a bridge (and not pyghidra / rizin)

The honest tradeoff: a fixed bridged subset instead of the whole live Ghidra API,
flat DTOs instead of an in-process object graph, and tight loops must batch
server-side. In return: a single typed .NET stack with no Python and no JVM in
the consumer, reviewable end to end.

## License

[Apache-2.0](LICENSE) — same as Ghidra, with which the server links.
