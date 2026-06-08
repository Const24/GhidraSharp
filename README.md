# GhidraSharp

<!-- CI badge — re-enable (remove these comment markers) after the first green run:
[![CI](https://github.com/Const24/GhidraSharp/actions/workflows/ci.yml/badge.svg)](https://github.com/Const24/GhidraSharp/actions/workflows/ci.yml)
-->

A typed **C# client for [Ghidra](https://ghidra-sre.org/)** over a small gRPC bridge.
No Python in the chain.

There is no official or popular C# binding to Ghidra — the community option is
the Python `ghidra_bridge`, and Ghidra's only first-party cross-language wire
protocol (TraceRmi) is debugger-scoped, not the static analysis API. GhidraSharp
fills that gap with a deliberately small, typed surface:

```
  ┌─────────────────────┐   gRPC (protobuf)  ┌─────────────────────────────┐
  │ Const24.GhidraSharp │   ──────────────>  │ GhidraSharpServer (Java)    │
  │ C# client (net8/10) │   <──────────────  │ Ghidra-as-library, headless │
  └─────────────────────┘                    └─────────────────────────────┘
```

* **`proto/ghidrasharp.proto`** — the single source of truth for the wire
  contract. Both sides generate from it; nobody hand-writes DTOs.
* **`src/GhidraSharp/`** — the C# client library (NuGet `Const24.GhidraSharp`,
  namespace `Const24.GhidraSharp`). Generates gRPC client stubs from the proto
  at build via `Grpc.Tools`.
* **`src/GhidraSharp.Sample/`** — a console smoke test for the bridge.
* **`server/`** — the Java gRPC server that runs Ghidra as a library and serves
  decompilation / analysis (Gradle build).

## Requirements

* **.NET 8 or later** — the client multi-targets `net8.0` and `net10.0`.
* **JDK 21 or later** — to build and run the server (Ghidra 12.1 requires 21+).
* **Ghidra 12.1** — point `GHIDRA_INSTALL_DIR` at the install.

## Install

```sh
dotnet add package Const24.GhidraSharp
```

That gets you the C# client. You also need a running `GhidraSharpServer` to talk
to — build it from this repo (see [Running the server](#running-the-server)).

## Quickstart

From a raw firmware dump (`.bin`) to its decompiled functions — no prior Ghidra
knowledge required:

```csharp
using Const24.GhidraSharp;

// connect to a running server (see "Running the server" below)
using var ghidra = GhidraClient.Connect("http://127.0.0.1:50080");

// import the binary, auto-analyze it, and save it as a project.
// languageId is the target chip's processor — here Renesas SH-2A (Subaru ECUs).
var program = await ghidra.CreateProjectAsync(
    binaryPath:      @"C:\firmware\ecu.bin",
    projectLocation: @"C:\firmware\ghidra-projects",
    projectName:     "ecu",
    languageId:      "SuperH:BE:32:SH-2A");

Console.WriteLine($"{program.FunctionCount} functions found");

// list every function Ghidra recovered
var functions = await ghidra.ListFunctionsAsync();
foreach (var fn in functions)
    Console.WriteLine($"  {fn.EntryPoint}  {fn.Name}");

// decompile the first one to C
var dec = await ghidra.DecompileAtAsync(functions[0].EntryPoint);
Console.WriteLine(dec.CCode);
```

`languageId` is the only Ghidra-specific input: pick the processor that matches
your chip — e.g. `SuperH:BE:32:SH-2A`, `ARM:LE:32:v7`, `x86:LE:64:default`.
Already have an analyzed Ghidra project? Open it with `OpenProgramAsync(...)`.

Prefer the client to own the process? `GhidraServer.StartAsync(...)` spawns the
server, hands you a connected `Client`, and stops it on dispose.

### Running the server

```sh
cd server
./gradlew writeServerArgs                 # generate the launch argfile (once)
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1_PUBLIC java @build/ghidrasharp-java.args
```

## Status

Working bridge. The surface grows one RPC at a time as consumers need it.

* `Ping` — liveness + Ghidra version
* `OpenProgram` — open an analyzed project, or import a binary
* `DecompileFunction` / `DecompileFunctions` (batch, server-streamed) — function → C
* `ListFunctions` — functions (+ callees), built to query client-side with LINQ
* `GetFunction` — full detail for one function (typed signature, params, locals, callers)
* `GetReferencesTo` / `GetReferencesFrom` — cross-references (xrefs)
* `ListSymbols` / `GetSymbolsAt` — symbols by name or address
* `RenameSymbol` — record a finding back onto the program (needs `writable: true`; in-memory unless saved)
* `ReadBytes` — raw program memory (feeds a pure-C# byte/table layer)
* `GetInstructions` — the disassembly listing (mnemonic, operands, bytes)
* `GetDataAt` / `ListDataTypes` / `ApplyDataType` — defined data and data types
* `GetInstructionDetail` — one instruction's structured operands + raw PCode
* `GetComments` / `SetComment` — comments (all five Ghidra types)
* `GetBookmarks` / `SetBookmark` — bookmarks
* `CreateProject` — import a binary into a new persistent project (`.gpr`/`.rep`), analyzed + saved
* `SaveProgram` — persist edits (renames, applied types, comments) to disk
* `RunScript` — escape hatch: run any GhidraScript and capture its output

Architecture-agnostic by construction — it just forwards a Ghidra language id, so
the same code drives any processor Ghidra supports. Parity verified byte-for-byte
against pyghidra on three very different ISAs — SH-2A firmware, JVM bytecode, and
an x86-64 PE (see [bench/README](https://github.com/Const24/GhidraSharp/blob/main/bench/README.md#multi-architecture)).

The public C# API exposes only hand-written, documented result types
(`ProgramInfo`, `GhidraFunction`, `Decompilation`, `GhidraReference`, …); the
generated gRPC wire types are internal. Names follow Ghidra's own terms so they
read right to a Ghidra user, with XML docs that also explain each concept to a
.NET developer new to Ghidra. Validated **byte-for-byte against pyghidra across
the whole API** (functions, symbols, decompilation, instructions, xrefs, bytes,
function detail, data types) at comparable speed — see the
[parity report](https://github.com/Const24/GhidraSharp/blob/main/bench/REPORT.md) and [bench/](https://github.com/Const24/GhidraSharp/tree/main/bench).

## Building the client

```sh
dotnet build GhidraSharp.slnx
```

## Testing

A test pyramid; the fast tiers need no Ghidra and are the CI badge above.

```sh
# fast — C# unit + contract tests (client ↔ in-process fake server). No Ghidra/JVM.
dotnet test tests/GhidraSharp.Tests --filter "Category!=Integration"

# Java service mapping tests (JUnit 5 + in-process gRPC + a fake engine)
cd server && ./gradlew test

# integration — real Ghidra end-to-end (spawns the server, builds a JVM target with
# javac, asserts decompile/rename+save/space-qualified-address behaviours). Gated:
# skipped unless GHIDRA_INSTALL_DIR is set and the launch argfile exists.
cd server && ./gradlew writeServerArgs            # once, to produce the argfile
dotnet test tests/GhidraSharp.Tests --filter "Category=Integration"
```

[`bench/`](https://github.com/Const24/GhidraSharp/tree/main/bench) is the acceptance + benchmark layer (byte-for-byte parity vs
pyghidra); `python bench/verify.py` runs it. Tests under [`tests/`](https://github.com/Const24/GhidraSharp/tree/main/tests) and
`server/src/test` are the unit/contract/integration layers.

## Scope — what's bridged, and what isn't

GhidraSharp is **not** a mirror of the entire Ghidra API, and doesn't try to be.
The goal is a curated, typed, documented surface over the **core RE operations**
(above), each one proven byte-identical to pyghidra. What it intentionally does
**not** expose:

* **Arbitrary Ghidra API / live object graph** — you get flat result records, not
  walkable Ghidra objects.
* **Decompiler internals** — C text, a typed signature, and per-instruction **raw
  PCode** are exposed, but not the decompiler's high PCode / `HighFunction`
  (data-flow SSA) or C-token↔address markup.
* **In-process scripting semantics** — no ad-hoc evaluation of Java/Python against
  the live program.

For everything outside the typed surface there's **`RunScript`**: it runs any
GhidraScript against the current program and returns its output. So you're never
*more* limited than pyghidra — just less typed for the long tail. Typed RPCs are
added on demand as consumers need them.

The trade for these limits: a single typed .NET stack, no Python and no JVM in the
consumer, reviewable end to end, and a correctness story you can verify yourself
(`bench/`).

**Security:** the server is unauthenticated and exposes `RunScript` (arbitrary
GhidraScript) plus file and memory access, so it **binds to loopback only** and is
meant to be a local tool driven by a client on the same host — never expose its port.

## License

[Apache-2.0](https://github.com/Const24/GhidraSharp/blob/main/LICENSE) — same as Ghidra, with which the server links.
