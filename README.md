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

Vertical slice in progress: `Ping` → `OpenProgram` → `DecompileFunction`. The
bridged surface grows one RPC at a time as consumers need it.

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
