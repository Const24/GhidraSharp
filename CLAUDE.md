# GhidraSharp — maintainer guide

Guidance for anyone (human or agent) **maintaining** GhidraSharp: a typed **C#
client for Ghidra** over a small gRPC bridge. This file captures the decisions
and traps that are not obvious from the code.

`README.md` owns everything a *consumer* needs — architecture diagram,
prerequisites, install, quickstart, running the server, `GhidraServerPool` /
`BatchExtractor` usage, the full RPC list, build/test commands, scope, and the
loopback security posture. This file does **not** restate those; it points at
README and covers what README does not.

## Two artifacts that must move together

| Artifact | Built from | Ships as |
|---|---|---|
| C# client | `src/GhidraSharp/` (`net8.0;net10.0`) | NuGet `Const24.GhidraSharp` |
| Java server | `server/` (Gradle, Ghidra-as-library) | NuGet `Const24.GhidraSharp.Server` + a GitHub Release zip |

`proto/ghidrasharp.proto` is the single source of truth for the wire contract —
both sides generate from it, nobody hand-writes DTOs. On the C# side the
generated types are `Access="Internal"` and reach the tests through
`InternalsVisibleTo`; the only public surface is the hand-written result records
in `Model.cs`.

**Version them in lockstep.** Three files carry the same version and move
together:

- `src/GhidraSharp/GhidraSharp.csproj` (`<Version>`)
- `src/GhidraSharp.Server/GhidraSharp.Server.csproj`
- `server/build.gradle` (`version = ...`)

A client and a server from different versions can disagree about the proto. The
`Ping` handshake (→ `server_version`, and gRPC `UNIMPLEMENTED` → "update your
server") exists precisely to make that skew *loud* instead of mysterious.

## Adding an RPC — the full stack, in order

Miss a layer and it either won't compile or will silently no-op in tests:

1. `proto/ghidrasharp.proto` — the rpc + its request/reply messages.
2. `GhidraEngine` (Java interface) + any result records.
3. `GhidraLibraryEngine` — the real implementation against the Ghidra API.
4. `StubEngine` — the no-Ghidra stub.
5. `GhidraSharpServiceImpl` — proto ↔ engine mapping (+ imports).
6. C# `Model.cs` — the public record, and `GhidraClient` — the async method.
7. `FakeEngine` / `FakeServer` (tests) — canned responses.
8. Tests: a Java service test, a C# contract test against the fake, and — if it
   touches real Ghidra behaviour — an integration test.
9. Rebuild the server dist (see below).

**The tests project does not generate its own proto stubs** — it reaches the
generated types via `InternalsVisibleTo`. Adding a `<Protobuf>` item there
produces a duplicate-type build break.

**Verify the Ghidra API before writing against it.** Ghidra's API is not what an
LLM remembers it to be: `DefinedDataIterator.definedStrings(Program)` does not
exist in 12.1 — the working call is
`DefinedDataIterator.byDataInstance(program, StringDataInstance::isString)`.
Confirm signatures with `javap` against the Ghidra jars rather than guessing.

## Rebuild the server dist (the trap that bites hardest)

Adding an RPC to the client and the proto is **not** enough. The on-disk server
distribution (`server/build/install/ghidrasharp-server`, and the packaged zip)
is a build artifact — if you don't rebuild it, a consumer calling the new RPC
fails at **run time**, not compile time, with "server does not implement 'X'".

```sh
server/gradlew -p server installDist    # needs GHIDRA_INSTALL_DIR
```

If Gradle refuses because the install dir is non-empty, delete it first. This has
already broken a downstream consumer once — treat rebuilding the dist as the
final mandatory step of adding an RPC.

## Build & test — and the silent-skip trap

README lists the commands. The maintainer-critical subtlety it doesn't spell out:
**a green `dotnet test` can mean nothing was really tested.** The integration and
pool tests are gated by `Assert.SkipUnless` and **skip silently** when
prerequisites are absent:

- `EngineIntegrationTests` needs `GHIDRA_INSTALL_DIR` + `JAVA_HOME` + the argfile
  `server/build/ghidrasharp-java.args`.
- `ServerPoolTests` uses the stub engine and needs only `JAVA_HOME` + that argfile.

Run `cd server && ./gradlew writeServerArgs` first, then — before believing a
green run touched real Ghidra — confirm the integration tests actually **ran**:

```sh
dotnet test -- --filter-trait "Category=Integration"   # expect 14 passed, 0 skipped
```

**The filter must follow `--`.** These tests run on Microsoft.Testing.Platform;
VSTest's `--filter "Category=Integration"` is not rejected, it is *silently
ignored* (only a `warning MTP0001`) and the whole suite runs — which hands you
exactly the false picture this check exists to prevent. CI cannot cover this gap
either: a runner has no Ghidra install.

## Server pool memory knobs

`GhidraServerPool` runs **N independent server JVMs** — the server is
single-program by design, so corpus-scale work means N instances, not N threads.
Four constants in `GhidraLibraryEngine.java` keep an N-way pool alive under
memory pressure; none is arbitrary:

- **`DECOMP_RECYCLE_EVERY = 1500`** (`:77`) — the **primary RSS control** for a
  whole-program decompile. One `DecompInterface` owns one native `decompile.exe`
  whose resident memory only *grows* across a sweep; on a ~90k-function binary it
  creeps to multiple GB per server and breaks any RAM-bounded pool. Disposing +
  rebinding the interface every 1500 functions (`:197`) resets it. This — not any
  size cap — is what keeps each pooled server within a predictable budget.
- **`DECOMP_MAX_INSTRUCTIONS = 50_000`** (`:84`, below Ghidra's 100k default) —
  the only lever that bounds a single pathological function. Its peak lives in the
  **native** `decompile.exe`, entirely outside the JVM heap: one such function
  once committed ~18 GB, and `-Xmx` cannot touch it. A bailed function yields a
  failure marker; legitimate functions (well under 10–20k instructions) are
  unaffected. Lower it to 20–30k if a monster still slips through at high N.
- **`DECOMP_MAX_PAYLOAD_MB = 50`** (`:78`) — a belt-and-braces per-function
  payload ceiling. It equals Ghidra's own default, so in practice it adds no
  protection beyond the two controls above; do not mistake it for the RSS lever.
- **`recycleDecompiler()` is best-effort and never throws.** On failure the
  binary's stream ends via `onCompleted`, not `onError` — `BatchExtractor`
  buffers and writes the `.c` only *after* the loop, so a hard abort would have
  discarded the entire decompile of a large binary.

`GhidraServerPool` also has a `JvmMaxHeapMb` ceiling (not a reservation — there is
no `-Xms`), so small targets still use well under 1 GB. On a constrained host,
lower it toward host-RAM/N.

## Environment & build traps

- **Gradle silently fakes a Ghidra install.** `server/build.gradle` falls back to
  a hardcoded `C:/ghidra_12.1_PUBLIC` when `GHIDRA_INSTALL_DIR` is unset (`:21`).
  So `./gradlew` appears to "work" with no env var while the C# side throws
  `DirectoryNotFoundException`; on a machine lacking that exact path you get a
  wall of `cannot find symbol: ghidra.*` instead of a clear message. Always set
  `GHIDRA_INSTALL_DIR` explicitly.
- **`GHIDRASHARP_ENGINE=stub`** runs a real gRPC server backed by the
  transport-only `StubEngine` — no Ghidra, no `GHIDRA_INSTALL_DIR` needed. Useful
  for exercising the wire without an install. Anything else selects the real
  `GhidraLibraryEngine`.
- **`GHIDRASHARP_PORT`** overrides the listen port (default `50080`).
- **Source-build loop:** use `./gradlew writeServerArgs` (emits a Java `@argfile`
  at `server/build/ghidrasharp-java.args`) and launch with
  `java @build/ghidrasharp-java.args`, or feed the argfile to
  `GhidraServerOptions.ArgFile`. This is the path the integration/pool tests take;
  `installDist` is for producing the shippable dist.
- **Server resolution** (`GhidraServer.StartAsync`): explicit `ServerDirectory`
  → explicit `ArgFile` → env `GHIDRASHARP_SERVER_DIR` →
  `AppContext.BaseDirectory/ghidrasharp-server` (dir must contain `lib/`).
  Explicit options beat the ambient env; callers should not have to know paths.
- **MSBuild output is locale-dependent here** (currently emits Russian-locale
  text). Scrape **exit codes**, not stdout, for "error"/"warning" when scripting a
  build.

## The enforced contract — four root files

The build *is* the gate; there is no separate lint step to drift from it. Nothing
in the chain sits above the repo root, so a clone builds identically on a fork or
a runner. Marked `shared-core v1` — byte-identical to RomForge.Lab's copy; sync by
hand when either changes.

- **`Directory.Build.props`** — `LangVersion`/`Nullable`/`ImplicitUsings`,
  `AnalysisLevel=latest-recommended`, `EnforceCodeStyleInBuild`,
  `GenerateDocumentationFile`, and `TreatWarningsAsErrors` **unconditionally** (one
  bar locally and on CI). Tune noise through `.editorconfig` severities, never by
  making `TreatWarningsAsErrors` conditional. WIP escape hatch:
  `dotnet build -p:TreatWarningsAsErrors=false`.
- **`.editorconfig`** (`root = true`) — the style canon at **warning** severity, so
  the language server and the build push the same way. Carve-outs live here:
  `CS1591` off for what isn't shipped (tests/bench/sample), `CA1707`/`CA1711` off
  for xUnit naming. NB the glob is `[{tests,**/tests}/**.cs]` — `**/tests/` alone
  does **not** match a repo-root `tests/` folder.
- **`Directory.Packages.props`** — central package versions; csprojs carry a
  `PackageReference` with no version.
- **`global.json`** — pins the SDK band (`rollForward: latestFeature`).

Deliberately absent: lock files (contributor and dependabot friction; consumers
are pinned by the nuspec) and `nuget.config`.

## Conventions the tooling does not enforce

- File-scoped namespaces under `Const24.GhidraSharp`. The public surface is the
  hand-written records in `Model.cs`; a missing XML doc there is a build error.
- **Tests:** xUnit **v3** on Microsoft.Testing.Platform — the test project is an
  `Exe`, there is no `Test.Sdk`/VSTest runner, and skip is native
  (`Assert.SkipUnless`). The integration gate is `[Trait("Category","Integration")]`.
  Java: JUnit 5.
- **Ghidra jars are on the main compile/runtime classpath only, never the test
  set** — that is why `server/gradlew test` runs on any machine.
- **Paired protobuf versions.** C# `Google.Protobuf` 3.35.x and Java
  `protobuf-java` 4.35.0 are the *same* protobuf release and a deliberate set;
  `Ghidra/Debug/**` is excluded from the classpath because it ships 4.31. Bump one
  side alone and the wire breaks.
- **`.gitattributes` forces LF** for source and `gradlew`; only `*.bat` stays
  CRLF.
- **`src/GhidraSharp.Server/build/` is a *tracked* MSBuild folder** (it holds the
  `.targets` that copy the server into a consumer's output). A past `.gitignore`
  once swallowed it — don't let a blanket `build/` ignore re-hide it.

## Settled decisions — do not re-litigate

- **The server is not embedded in the client NuGet, and is not auto-downloaded at
  run time.** Both were considered and rejected: auto-download breaks on
  read-only directories, mismatches `dotnet publish` output, and is
  non-deterministic. The ship path is the **`Const24.GhidraSharp.Server`
  package**, whose MSBuild `.targets` copy `ghidrasharp-server/` into the
  consumer's build output. One `dotnet add package Const24.GhidraSharp.Server`
  brings the client with it.
- **`FindStrings` is a server-side RPC, not client-side composition.** An earlier
  client filtered on Ghidra's sanitized `s_`/`u_` label instead of the decoded
  text, so it silently dropped multi-word, punctuated, renamed, and imported
  strings. Match on the text, server-side.
- **The server binds loopback only and is unauthenticated** — it exposes
  `RunScript` (arbitrary GhidraScript) plus file/memory access, so it must never
  be reachable off the host. This is a load-bearing safety property, not a
  default to relax.
- Ghidra **12.1+** and **JDK 21+** are hard external prerequisites — same as for
  any Ghidra tool. Don't try to engineer them away.

## Release process

Published NuGet versions are **immutable** — they cannot be overwritten or
deleted, only unlisted. A mistake means bumping the version, so get it right
before pushing. Order matters:

1. `dotnet nuget push` the **client** first (`.snupkg` alongside it is picked up
   automatically). The server package *depends* on the client; publish it first or
   its dependency won't resolve.
2. `dotnet nuget push` the **server** package.
3. `git push` main + the `vX.Y.Z` tag.
4. Create the **GitHub Release** for that tag and attach
   `server/build/distributions/ghidrasharp-server-X.Y.Z.zip`. This step is not
   optional — the README and the client's runtime error message both point users
   at Releases to download the server. If the `gh` CLI isn't available, use the
   web UI.

Publishing is outward-facing and irreversible: do it on an explicit instruction,
never on an ambiguous signal.

## Repo hygiene

Apache-2.0 (matching Ghidra, which the server links). The repo is **public**: no
binaries, no firmware, no ROMs, no third-party definition files, no private
paths, no customer or downstream names — `bench/` is deliberately clean-room and
says so. A leak in git history is not something you can quietly undo.

## No CI (yet)

There is currently **no CI** — `.github/` is absent and there is no README badge.
Local commands are the only safety net, which is exactly why the silent-skip trap
above matters.

When CI is restored, a build+test workflow is nearly free enforcement:
`TreatWarningsAsErrors` and `EnforceCodeStyleInBuild` are unconditional, so the
build already *is* the analyzer and style gate — no separate lint step to keep in
sync. Two things it still would **not** buy you: a runner has no Ghidra, so the
integration and pool tiers skip there exactly as they do locally; and releases stay
manual until a `publish.yml` (tag → pack → push → attach the server zip) exists.

## Backlog

- Restore CI, plus a `publish.yml` (above).
- A possible future RPC: bulk typed `DataItem`s + an address-keyed xref graph.
  Deliberately **not** built — it waits for a real consumer need, not a
  speculative one.
