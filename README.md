# GhidraSharp

[![CI](https://github.com/Const24/GhidraSharp/actions/workflows/ci.yml/badge.svg)](https://github.com/Const24/GhidraSharp/actions/workflows/ci.yml)

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
an x86-64 PE (see [bench/README](bench/README.md#multi-architecture)).

The public C# API exposes only hand-written, documented result types
(`ProgramInfo`, `GhidraFunction`, `Decompilation`, `GhidraReference`, …); the
generated gRPC wire types are internal. Names follow Ghidra's own terms so they
read right to a Ghidra user, with XML docs that also explain each concept to a
.NET developer new to Ghidra. Validated **byte-for-byte against pyghidra across
the whole API** (functions, symbols, decompilation, instructions, xrefs, bytes,
function detail, data types) at comparable speed — see the
[parity report](bench/REPORT.md) and [bench/](bench/).

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

[`bench/`](bench/) is the acceptance + benchmark layer (byte-for-byte parity vs
pyghidra); `python bench/verify.py` runs it. Tests under [`tests/`](tests/) and
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

[Apache-2.0](LICENSE) — same as Ghidra, with which the server links.
