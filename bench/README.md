# Benchmarks & parity tests

Proof that GhidraSharp is **not worse than official pyghidra** — same correctness,
comparable speed — across the whole bridged API, not just decompilation.

## The idea (why this is a strong test)

GhidraSharp and pyghidra drive the **same Ghidra** with the **same calls**. So for
any operation the bridge's output *must* equal pyghidra's, byte for byte. Anything
else is a bridge bug. That makes this both:

- a **correctness test** — assert the two dumps are identical (CI gate: non-zero exit on mismatch), and
- a **benchmark** — time each side doing the same work.

Two extractors emit an identical canonical dump per RPC:

- [`GhidraSharp.Parity`](GhidraSharp.Parity/) — through the bridge (`GhidraClient`, auto-spawns the server).
- [`pyghidra_extract.py`](pyghidra_extract.py) — through pyghidra in-process, mirroring the server's engine.

[`compare.py`](compare.py) diffs them by SHA-256 and writes [`REPORT.md`](REPORT.md).

Covered: `functions`, `symbols`, `decompile`, `instructions`, `xrefs_to`, `bytes`.

## Run

```pwsh
pwsh bench/run.ps1 <path/to/PROJECT.gpr>
```

Needs `GHIDRA_INSTALL_DIR` and `JAVA_HOME`, plus `pyghidra` for the baseline.
The result lands in [`REPORT.md`](REPORT.md) (committed so visitors see it without
running anything). Dumps under `bench/out/` are git-ignored.

## Multi-architecture

The bridge only forwards a Ghidra language id, so it is processor-agnostic.
Parity was verified byte-for-byte against pyghidra on three very different ISAs
(build a project from the binary with `--create-project`, then run both extractors):

| Target | Ghidra language | Result |
| --- | --- | --- |
| SuperH **SH-2A** (Subaru firmware) | `SuperH:BE:32:SH-2A` | 8/8 identical |
| **JVM** bytecode (`.class`) | `JVM:BE:32` | 8/8 identical |
| **ARM64** | `AARCH64:LE:64:v8A` | 8/8 identical |
| **ARM64 big-endian** | `AARCH64:BE:64:v8A` | 8/8 identical |
| **ARM32** | `ARM:LE:32:v8` | 8/8 identical |
| **RISC-V 64** | `RISCV:LE:64` | 8/8 identical |
| **x86-32** | `x86:LE:32` | 8/8 identical |
| **x86-64** (PE) | `x86:LE:64` | 7/8 identical — see note |

The RISC/x86-32 objects are built from [`multiarch_sample.c`](multiarch_sample.c)
with `clang -c -target <triple>` (no downloads, no sysroot — relocatable ELF
objects Ghidra reads directly); Ghidra auto-detects the language from the ELF
header. Coverage spans little- and big-endian, 32- and 64-bit, CISC, RISC, and a
stack VM.

**Note on the x86-64 decompile:** one function out of 2288 decompiles
differently. This is **Ghidra's own decompiler being nondeterministic** there,
not a bridge difference — running `pyghidra_extract.py` twice on the same program
yields two different decompilations of that same function. Every other capability
(functions, symbols, instructions, xrefs, bytes, function detail, data types) is
byte-identical. So the bridge is a faithful conduit; its decompiler output equals
pyghidra's except where Ghidra itself is not deterministic.
