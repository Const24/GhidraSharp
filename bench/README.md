# Benchmarks

Face-to-face validation of the GhidraSharp bridge against **pyghidra**
(in-process), on the same already-analyzed Ghidra project. Both sides drive the
same Ghidra the same way (open the existing `.rep` read-only, `DecompInterface`,
`getFunctions(true)`, `getC()`), so any difference would be the bridge's fault.

## Running

```sh
# 1) Bridge side: decompile every function, dump the C, report throughput
dotnet run --project src/GhidraSharp.Sample -- \
  --spawn --project <path/to/PROJ.gpr> --rom <PROGRAM> \
  --decompile-all --dump bench/bridge_dump.txt

# 2) pyghidra side: same project, same dump format
#    (needs GHIDRA_INSTALL_DIR + JAVA_HOME, same as the bridge)
python bench/pyghidra_decompile_all.py <path/to/PROJ.gpr> bench/pyghidra_dump.txt

# 3) Compare
sha256sum bench/bridge_dump.txt bench/pyghidra_dump.txt
diff -q bench/bridge_dump.txt bench/pyghidra_dump.txt   # empty => identical
```

## Result (Ghidra 12.1, SH-2A corpus ROM A2WC000E, 2076 functions)

| | functions | time | throughput | dump |
|---|---|---|---|---|
| pyghidra (in-process) | 2076 ok / 0 fail | ~11.9 s | ~174 func/s | 1,867,935 B |
| GhidraSharp (gRPC bridge) | 2076 ok / 0 fail | ~11.7 s | ~177 func/s | 1,867,935 B |

* **Correctness:** the two dumps are **byte-for-byte identical** (same SHA-256).
  The bridge is a faithful conduit to Ghidra — zero divergence across ~1.9 MB of C.
* **Performance:** **equal** within noise (the native decompiler dominates;
  the gRPC round trip is amortized by batching the whole program into one
  server-streaming call, so per-call IPC overhead disappears).

Dumps (`*_dump.txt`) are git-ignored; regenerate with the commands above.
