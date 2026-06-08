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
