"""Face-to-face benchmark vs GhidraSharp.

Decompiles every function in an already-analyzed Ghidra project via pyghidra
(in-process), mirroring the server's GhidraLibraryEngine exactly (open the
existing .rep read-only, DecompInterface, getFunctions(True), getC()). Writes a
canonical per-function dump so it can be diffed byte-for-byte against the
bridge's dump (`--decompile-all --dump`), and prints decompile throughput.

    python bench/pyghidra_decompile_all.py <project.gpr|dir> <dump-file>

Env: GHIDRA_INSTALL_DIR, JAVA_HOME (the same Ghidra/Java the bridge uses).
"""
from __future__ import annotations

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


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: pyghidra_decompile_all.py <project .gpr|dir> <dump-file>", file=sys.stderr)
        return 2

    project_dir, project_name = resolve_project(argv[0])
    dump_path = Path(argv[1])

    import pyghidra
    pyghidra.start(verbose=False)
    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    # sweep a stale lock from an interrupted session
    for lock in Path(project_dir, project_name + ".rep").glob("*.lock*"):
        try:
            lock.unlink()
        except OSError:
            pass

    project = GhidraProject.openProject(project_dir, project_name, False)
    try:
        program = None
        for df in project.getRootFolder().getFiles():
            if df.getContentType() == "Program":
                program = project.openProgram("/", df.getName(), True)  # read-only
                break
        if program is None:
            print("no Program found in project", file=sys.stderr)
            return 3

        fm = program.getFunctionManager()
        print(f"[pyghidra] {program.getName()} ({program.getLanguageID()}) functions={fm.getFunctionCount()}")

        dec = DecompInterface()
        dec.openProgram(program)

        ok = fail = 0
        t0 = time.perf_counter()
        with open(dump_path, "w", encoding="utf-8", newline="") as out:
            for f in fm.getFunctions(True):
                res = dec.decompileFunction(f, 60, TaskMonitor.DUMMY)
                if res and res.decompileCompleted():
                    ok += 1
                    out.write(f">>> {f.getEntryPoint().toString()}\n{res.getDecompiledFunction().getC()}")
                else:
                    fail += 1
        elapsed = time.perf_counter() - t0
        dec.dispose()

        per_sec = (ok + fail) / max(1e-9, elapsed)
        print(f"[pyghidra] decompiled {ok} ok / {fail} failed in {elapsed * 1000:.0f} ms ({per_sec:.0f} func/s)")
        print(f"[pyghidra] dump -> {dump_path}")
    finally:
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
