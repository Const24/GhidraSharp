# Acceptance & benchmarks

> Unit, contract and integration tests live in [`../tests/`](../tests/) and
> `../server/src/test` (run with `dotnet test` / `gradlew test`). This folder is
> the **acceptance + benchmark** layer: cross-tool parity against pyghidra.

Proof that GhidraSharp is **not worse than official pyghidra** — same output,
comparable speed — that anyone can reproduce **on their own machine in one
command, with no private data**.

## One click

```sh
python bench/verify.py
```

It builds the bridge, generates its own test targets, runs the full parity
harness against pyghidra on each, and writes [`REPORT.md`](REPORT.md). Exit code
is non-zero on any real mismatch (so it doubles as a CI gate).

Flags: `--quick` (JVM only, fast), `--no-risc` (skip the clang zoo), `--skip-build`.

## What you need

| Component | Needed for |
| --- | --- |
| **.NET SDK**, **JDK 21+** (`JAVA_HOME`), **Ghidra 12.x** (`GHIDRA_INSTALL_DIR`) | required — these also run the bridge itself |
| **Python + `pip install pyghidra`** | the vs-pyghidra baseline |
| **clang / LLVM** | optional — adds the ARM64 / ARM32 / RISC-V64 / x86-32 targets |

`verify.py` checks these and tells you exactly what's missing.

## No private data needed

The harness never ships or requires a real ROM. It builds its own targets from
tools you already have, so the comparison is fully reproducible by anyone:

- **JVM** — a tiny `.java` compiled with the JDK's `javac`
- **x86-64** — Ghidra's own bundled decompiler binary for your OS
- **RISC zoo** — [`multiarch_sample.c`](multiarch_sample.c) compiled with
  `clang -c -target <triple>` into relocatable ELF objects (no sysroot, no
  downloads); Ghidra detects the language from the ELF header

(Subaru firmware was used during our own development but is **intentionally not**
in this repo — everyone reproduces with the self-generated targets above.)

## Why this is a strong test (the oracle)

GhidraSharp and pyghidra drive the **same Ghidra** with the **same calls**, so
for any operation the bridge's output *must* equal pyghidra's, byte for byte —
anything else is a bridge bug. Each target is built into a Ghidra project, then
the same canonical dump (`functions`, `symbols`, `decompile`, `instructions`,
`xrefs_to`, `bytes`, `function_detail`, `datatypes`) is extracted via the bridge
and via pyghidra and compared by SHA-256.

## Pieces (used by `verify.py`, or runnable by hand)

- [`GhidraSharp.Parity`](GhidraSharp.Parity/) — extract canonical dumps via the **bridge**
- [`pyghidra_extract.py`](pyghidra_extract.py) — the same dumps via **pyghidra**
- [`compare.py`](compare.py) — diff one target's two dumps

## Latest result

See [`REPORT.md`](REPORT.md): every target byte-identical to pyghidra across all
eight capabilities. The one caveat is the **decompiler**: on a small fraction of
functions Ghidra's own decompiler is nondeterministic (running pyghidra twice on
the same program disagrees with itself there) — `verify.py` detects this and
reports it as a Ghidra property, not a bridge difference.

Validated across very different ISAs — SuperH SH-2A, JVM bytecode, ARM64
(LE **and** BE), ARM32, RISC-V64, x86-32, x86-64 — covering little/big-endian,
32/64-bit, CISC, RISC, and a stack VM.
