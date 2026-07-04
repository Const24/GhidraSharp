# GhidraSharp

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
* **Ghidra 12.1 or later** — point `GHIDRA_INSTALL_DIR` at the install (built and tested against 12.1).

## Install

**Batteries-included** — client + server, with the server bundled into your app's
output (ships with `dotnet publish`, found automatically at run time):

```sh
dotnet add package Const24.GhidraSharp.Server
```

**Client only** — if you connect to a `GhidraSharpServer` you run yourself
(see [Running the server](#running-the-server)):

```sh
dotnet add package Const24.GhidraSharp
```

Either way the machine that runs the server needs **JDK 21+** and a **Ghidra**
install (`GHIDRA_INSTALL_DIR`) — those aren't shipped.

## Quickstart

From a raw firmware dump (`.bin`) to its decompiled functions — install
`Const24.GhidraSharp.Server`, point `GHIDRA_INSTALL_DIR` at your Ghidra, and go.
No server to start, no paths but your firmware:

```csharp
using Const24.GhidraSharp;

// the Const24.GhidraSharp.Server package ships the server next to your app;
// StartAsync finds + runs it, and stops it on dispose.
await using var server = await GhidraServer.StartAsync();
var ghidra = server.Client;

// import a raw firmware dump and analyze it — no project to manage.
// languageId is the target chip's processor (here Renesas SH-2A, Subaru ECUs).
await ghidra.OpenProgramAsync(@"C:\firmware\ecu.bin", languageId: "SuperH:BE:32:SH-2A");

// list every function Ghidra recovered
var functions = await ghidra.ListFunctionsAsync();
foreach (var fn in functions)
    Console.WriteLine($"  {fn.EntryPoint}  {fn.Name}");

// decompile the first one to C
var dec = await ghidra.DecompileAtAsync(functions[0].EntryPoint);
Console.WriteLine(dec.CCode);
```

`languageId` is the only Ghidra-specific input: pick the processor that matches
your chip — e.g. `SuperH:BE:32:SH-2A`, `ARM:LE:32:v7`, `x86:LE:64:default`. Not
sure which? `ListLanguagesAsync()` enumerates every one Ghidra supports (filter
like `ListLanguagesAsync("SuperH")`).

That example is transient — nothing is written to disk. To **save a project**
(analyze once, reopen fast, persist renames) use
`CreateProjectAsync(binaryPath, projectLocation, projectName, languageId)` — it
writes `<projectName>.gpr` + a `<projectName>.rep` folder, which you reopen later
with `OpenProgramAsync(name, projectPath: @"...\ecu.gpr")`. Running your own (or a
shared) server instead? Skip `StartAsync` and use
`GhidraClient.Connect("http://127.0.0.1:50080")`.

### Running the server

There are two ways to run it:

* **Standalone (below)** — run the launcher; it stays up until you stop it, so it can
  be reused across many client runs, driven by non-.NET clients, or run as a service.
  Connect with `GhidraClient.Connect("http://127.0.0.1:50080")`.
* **Client-spawned** — `GhidraServer.StartAsync` (with `ServerDirectory`) launches and
  owns a server for one .NET app and stops it on dispose (see the Quickstart above).

Download `ghidrasharp-server-<version>.zip` from
[Releases](https://github.com/Const24/GhidraSharp/releases), unzip it, point
`GHIDRA_INSTALL_DIR` at your Ghidra install, and run the launcher (needs JDK 21+):

```powershell
# Windows (PowerShell)
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_12.1_PUBLIC"
.\ghidrasharp-server.ps1
```

```sh
# Linux / macOS
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC
./ghidrasharp-server.sh
```

It listens on `127.0.0.1:50080` and runs until you stop it (Ctrl+C, or close the
terminal — it shuts down gracefully; there is no idle timeout). Building from source
instead? `cd server && ./gradlew writeServerArgs`, then `java @build/ghidrasharp-java.args`.

### Parallel batch — `GhidraServerPool`

A single server is one-program-at-a-time. To chew through a whole corpus, run a pool
of N independent servers (N JVMs) and hand it the work: each item runs on one server,
per-item failures are captured, and a crashed server is restarted so the batch finishes.

```csharp
await using var pool = await GhidraServerPool.StartAsync(size: 8, new GhidraServerOptions());

var results = await pool.ForEachAsync(romPaths, async (ghidra, rom, ct) =>
{
    await ghidra.CreateProjectAsync(rom, projectDir, Path.GetFileNameWithoutExtension(rom), ct: ct);
    // ... decompile / extract on this server
}, progress: new Progress<PoolProgress>(p => Console.WriteLine($"{p.Done}/{p.Total} ({p.Failed} failed)")));

foreach (var f in results.Where(r => !r.Ok))
    Console.WriteLine($"FAILED {f.Item}: {f.Error?.Message}");
```

Sizing: ~1.5–2 GB per JVM with Ghidra loaded → ~24 on a 64 GB box.

## Status

Working bridge. The surface grows one RPC at a time as consumers need it.

* `Ping` — liveness + Ghidra version
* `OpenProgram` — open an analyzed project, or import a binary
* `DecompileFunction` / `DecompileFunctions` (batch, server-streamed) — function → C
* `ListFunctions` — functions (+ callees), built to query client-side with LINQ
* `GetFunction` — full detail for one function (typed signature, params, locals, callers)
* `GetReferencesTo` / `GetReferencesFrom` — cross-references (xrefs)
* `GetFunctionReferences` — every reference out of a function's body (e.g. its table data-refs)
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
* `CloseProgram` — close the current program, releasing its on-disk lock (frees a pooled server for the next item)
* `RunScript` — escape hatch: run any GhidraScript and capture its output
* `ListLanguages` — the processor languages Ghidra supports (its language picker), to pick a `languageId`

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

## Versioning

The client and server share one wire contract, so keep their versions matched —
install a server release of the same version as the `Const24.GhidraSharp` package.
Updating the NuGet package does not touch your server folder; download the matching
server release too. Mismatches fail loudly, not silently: `PingAsync().ServerVersion`
reports the server's version, and calling an RPC a too-old server lacks throws a
clear error telling you to update it.

## Building the client

```sh
dotnet build GhidraSharp.slnx
```

## Testing

A test pyramid; the fast tiers need no Ghidra and run anywhere.

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
