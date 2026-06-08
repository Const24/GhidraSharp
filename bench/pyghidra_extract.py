"""Face-to-face baseline for GhidraSharp.

Extracts a canonical dump of every operation the bridge exposes, computed
in-process via pyghidra with the SAME Ghidra calls the server's engine uses, in
the SAME canonical format as bench/GhidraSharp.Parity. The two dumps must be
byte-for-byte identical (same engine => same output); differences are bridge bugs.

    python bench/pyghidra_extract.py <project.gpr|dir> <out-dir>

Env: GHIDRA_INSTALL_DIR, JAVA_HOME.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def resolve_project(arg: str) -> tuple[str, str]:
    p = Path(arg)
    if p.suffix in (".gpr", ".rep"):
        return str(p.parent), p.stem
    if p.is_dir():
        gpr = next(p.glob("*.gpr"), None)
        if gpr is None:
            raise SystemExit(f"no .gpr project under {p}")
        return str(gpr.parent), gpr.stem
    raise SystemExit(f"not a .gpr/.rep or directory: {p}")


def b(x) -> str:
    return "true" if x else "false"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: pyghidra_extract.py <project.gpr|dir> <out-dir>", file=sys.stderr)
        return 2

    project_dir, project_name = resolve_project(argv[0])
    out = Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)

    import pyghidra
    pyghidra.start(verbose=False)
    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    for lock in Path(project_dir, project_name + ".rep").glob("*.lock*"):
        try:
            lock.unlink()
        except OSError:
            pass

    project = GhidraProject.openProject(project_dir, project_name, False)
    timings: dict[str, dict] = {}

    def timed(name, fn):
        t0 = time.perf_counter()
        count = fn()
        ms = round((time.perf_counter() - t0) * 1000)
        timings[name] = {"ms": ms, "count": count}
        print(f"[py] {name}: {count} in {ms} ms")

    try:
        program = None
        for df in project.getRootFolder().getFiles():
            if df.getContentType() == "Program":
                program = project.openProgram("/", df.getName(), True)
                break
        if program is None:
            print("no Program in project", file=sys.stderr)
            return 3

        fm = program.getFunctionManager()
        listing = program.getListing()
        memory = program.getMemory()
        refmgr = program.getReferenceManager()
        symtab = program.getSymbolTable()
        mon = TaskMonitor.DUMMY
        print(f"[parity/py] {program.getName()} ({program.getLanguageID()}) functions={fm.getFunctionCount()}")

        # Functions sorted by entry address string (matches the C# side).
        funcs = sorted(fm.getFunctions(True), key=lambda f: f.getEntryPoint().toString())

        def functions():
            lines = []
            for f in funcs:
                calls = ";".join(sorted(c.getName() for c in f.getCalledFunctions(mon)))
                lines.append(f"{f.getEntryPoint().toString()}\t{f.getName()}\t{f.getBody().getNumAddresses()}"
                             f"\t{f.getParameterCount()}\t{b(f.isThunk())}\t{calls}\n")
            (out / "functions.txt").write_text("".join(lines), encoding="utf-8", newline="")
            return len(funcs)

        def symbols():
            rows = []
            for s in symtab.getAllSymbols(False):
                rows.append((s.getAddress().toString(), s.getName(), str(s.getSymbolType()),
                             str(s.getSource()), b(s.isPrimary()), b(s.isGlobal())))
            rows.sort(key=lambda r: (r[0], r[1], r[2]))
            (out / "symbols.txt").write_text("".join("\t".join(r) + "\n" for r in rows),
                                             encoding="utf-8", newline="")
            return len(rows)

        def decompile():
            dec = DecompInterface()
            dec.openProgram(program)
            parts = []
            for f in funcs:
                res = dec.decompileFunction(f, 60, mon)
                if res and res.decompileCompleted():
                    parts.append((f.getEntryPoint().toString(), res.getDecompiledFunction().getC()))
            dec.dispose()
            parts.sort(key=lambda p: p[0])
            (out / "decompile.txt").write_text("".join(f">>> {a}\n{c}" for a, c in parts),
                                               encoding="utf-8", newline="")
            return len(parts)

        def instructions():
            lines = []
            n = 0
            for f in funcs:
                end = f.getBody().getMaxAddress()
                it = listing.getInstructions(f.getEntryPoint(), True)
                for ins in it:
                    if ins.getAddress().compareTo(end) > 0:
                        break
                    lines.append(f"{ins.getAddress().toString()}\t{ins.getMnemonicString()}\t{ins.toString()}\n")
                    n += 1
            (out / "instructions.txt").write_text("".join(lines), encoding="utf-8", newline="")
            return n

        def xrefs_to():
            lines = []
            n = 0
            for f in funcs:
                rows = []
                for r in refmgr.getReferencesTo(f.getEntryPoint()):
                    rows.append((r.getToAddress().toString(), r.getFromAddress().toString(),
                                 r.getReferenceType().getName()))
                rows.sort(key=lambda r: (r[1], r[2]))
                for r in rows:
                    lines.append("\t".join(r) + "\n")
                    n += 1
            (out / "xrefs_to.txt").write_text("".join(lines), encoding="utf-8", newline="")
            return n

        def read_bytes():
            lines = []
            for f in funcs:
                addr = f.getEntryPoint()
                data = bytearray()
                for i in range(16):
                    try:
                        data.append(memory.getByte(addr.add(i)) & 0xFF)
                    except Exception:
                        break
                lines.append(f"{addr.toString()}\t{data.hex().upper()}\n")
            (out / "bytes.txt").write_text("".join(lines), encoding="utf-8", newline="")
            return len(funcs)

        timed("functions", functions)
        timed("symbols", symbols)
        timed("decompile", decompile)
        timed("instructions", instructions)
        timed("xrefs_to", xrefs_to)
        timed("bytes", read_bytes)

        (out / "timings.json").write_text(json.dumps(timings, indent=2), encoding="utf-8")
        print(f"[parity/py] done -> {out}")
    finally:
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
