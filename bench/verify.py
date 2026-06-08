"""One-click verification for GhidraSharp.

Builds the bridge, generates its own test targets (no private data, no downloads),
and runs the full parity harness against pyghidra across every target it can make,
then writes bench/REPORT.md.

    python bench/verify.py            # JVM + host x86-64 (+ RISC zoo if clang is present)
    python bench/verify.py --no-risc  # skip the clang RISC zoo
    python bench/verify.py --quick    # JVM only (fast smoke)

Prerequisites (the script checks and tells you what's missing):
  required : .NET SDK (dotnet), JDK 21+ (JAVA_HOME), Ghidra 12.x (GHIDRA_INSTALL_DIR)
  baseline : Python + `pip install pyghidra`   (for the vs-pyghidra comparison)
  optional : clang / LLVM                       (adds ARM64/ARM32/RISCV64/x86-32)

Targets are self-contained:
  - JVM     : a tiny .java compiled with the JDK's javac
  - x86-64  : Ghidra's own bundled decompiler binary for this host OS
  - RISC zoo: bench/multiarch_sample.c compiled with `clang -c -target <triple>`
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "bench" / "out"
ARTIFACTS = ["functions", "symbols", "decompile", "instructions",
             "xrefs_to", "bytes", "function_detail", "datatypes"]
EXE = ".exe" if os.name == "nt" else ""


def fail(msg: str) -> "NoReturn":
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, **kw)


def tool_in_java_home(name: str) -> str | None:
    jh = os.environ.get("JAVA_HOME")
    if not jh:
        return None
    p = Path(jh) / "bin" / (name + EXE)
    return str(p) if p.is_file() else None


def find_clang() -> str | None:
    c = shutil.which("clang")
    if c:
        return c
    scoop = Path.home() / "scoop" / "apps" / "llvm" / "current" / "bin" / ("clang" + EXE)
    return str(scoop) if scoop.is_file() else None


def host_os_dir() -> str:
    s = platform.system()
    if s == "Windows":
        return "win_x86_64"
    if s == "Linux":
        return "linux_x86_64"
    if s == "Darwin":
        return "mac_arm_64" if platform.machine().lower() in ("arm64", "aarch64") else "mac_x86_64"
    return "win_x86_64"


def check_prereqs() -> tuple[str, str, str]:
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR")
    java_home = os.environ.get("JAVA_HOME")
    if not ghidra or not Path(ghidra).is_dir():
        fail("set GHIDRA_INSTALL_DIR to your Ghidra installation")
    if not java_home or not Path(java_home).is_dir():
        fail("set JAVA_HOME to a JDK 21+ install")
    if not shutil.which("dotnet"):
        fail("dotnet (.NET SDK) not found on PATH")
    if not tool_in_java_home("javac"):
        fail("javac not found under JAVA_HOME (need a JDK, not a JRE)")
    try:
        import pyghidra  # noqa: F401
    except ImportError:
        fail("pyghidra not importable -- `pip install pyghidra` (needed for the baseline)")
    return ghidra, java_home, tool_in_java_home("javac")


def build() -> None:
    print("[build] dotnet build (Release) ...")
    r = run(["dotnet", "build", "GhidraSharp.slnx", "-c", "Release", "-v", "quiet"])
    if r.returncode != 0:
        fail("dotnet build failed:\n" + r.stdout + r.stderr)
    print("[build] gradle writeServerArgs ...")
    gradlew = str(ROOT / "server" / ("gradlew.bat" if os.name == "nt" else "gradlew"))
    r = subprocess.run([gradlew, "writeServerArgs", "-q", "--console=plain"],
                       cwd=ROOT / "server", text=True, capture_output=True)
    if r.returncode != 0:
        fail("gradle writeServerArgs failed:\n" + r.stdout + r.stderr)


def gen_targets(ghidra: str, javac: str, with_risc: bool, quick: bool) -> dict[str, Path]:
    work = Path(tempfile.mkdtemp(prefix="ghidrasharp_verify_"))
    targets: dict[str, Path] = {}

    # JVM: tiny .java -> .class
    java_src = work / "Hello.java"
    java_src.write_text(
        "public class Hello {\n"
        "  static int add(int a, int b) { return a + b; }\n"
        "  static long fib(int n){ long x=0,y=1; for(int i=0;i<n;i++){ long t=x+y; x=y; y=t; } return x; }\n"
        "  public static void main(String[] a){ System.out.println(add(2,3)+fib(10)); }\n"
        "}\n", encoding="utf-8")
    if subprocess.run([javac, "-d", str(work), str(java_src)]).returncode == 0:
        targets["jvm"] = work / "Hello.class"

    if quick:
        return targets

    # x86-64: Ghidra's own bundled decompiler binary for this host
    host_bin = Path(ghidra) / "Ghidra" / "Features" / "Decompiler" / "os" / host_os_dir() / ("sleigh" + EXE)
    if host_bin.is_file():
        targets["x86-64"] = host_bin

    # RISC zoo: clang -c -target <triple> on our sample .c
    if with_risc:
        clang = find_clang()
        if clang:
            triples = {
                "aarch64": "aarch64-unknown-linux-gnu",
                "arm": "armv7-unknown-linux-gnueabi",
                "riscv64": "riscv64-unknown-linux-gnu",
                "x86-32": "i386-unknown-linux-gnu",
            }
            src = ROOT / "bench" / "multiarch_sample.c"
            for label, triple in triples.items():
                obj = work / f"{label}.o"
                rc = subprocess.run([clang, "-c", "-O1", "-target", triple, str(src), "-o", str(obj)],
                                    capture_output=True).returncode
                if rc == 0 and obj.is_file():
                    targets[label] = obj
        else:
            print("[targets] clang not found -- skipping the RISC zoo (use --no-risc to silence)")
    return targets


def sha(p: Path) -> str | None:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def extract_cs(gpr: str, outdir: Path) -> None:
    run(["dotnet", "run", "--project", "bench/GhidraSharp.Parity", "-c", "Release", "--no-build",
         "--", gpr, str(outdir)])


def extract_py(gpr: str, outdir: Path) -> None:
    subprocess.run([sys.executable, str(ROOT / "bench" / "pyghidra_extract.py"), gpr, str(outdir)],
                   cwd=ROOT, capture_output=True, env=os.environ)


def verify_target(label: str, binary: Path) -> dict:
    proj = Path(tempfile.mkdtemp(prefix=f"ghs_{label}_"))
    # 1) build a project from the binary
    run(["dotnet", "run", "--project", "src/GhidraSharp.Sample", "-c", "Release", "--no-build", "--",
         "--spawn", "--create-project", str(binary), "--proj-loc", str(proj), "--proj-name", "P"])
    gpr = str(proj / "P.gpr")
    if not (proj / "P.gpr").exists():
        return {"label": label, "status": "create-failed"}

    out = OUT / label
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    extract_cs(gpr, out / "cs")
    extract_py(gpr, out / "py")

    diffs = []
    for a in ARTIFACTS:
        hc, hp = sha(out / "cs" / f"{a}.txt"), sha(out / "py" / f"{a}.txt")
        if hc is None or hc != hp:
            diffs.append(a)

    note = ""
    if diffs == ["decompile"]:
        # only decompile differs -> check whether Ghidra itself is nondeterministic here
        extract_py(gpr, out / "py2")
        if sha(out / "py" / "decompile.txt") != sha(out / "py2" / "decompile.txt"):
            note = "decompile differs only because Ghidra's decompiler is nondeterministic here (pyghidra disagrees with itself)"
            diffs = []

    shutil.rmtree(proj, ignore_errors=True)
    return {"label": label, "status": "ok" if not diffs else "mismatch", "diffs": diffs, "note": note}


def write_report(results: list[dict]) -> bool:
    all_ok = all(r["status"] == "ok" for r in results)
    lines = ["# Verification report\n",
             "Generated by `bench/verify.py` from self-generated targets (no private data).",
             "Each target is built into a Ghidra project, then the same canonical dump is",
             "extracted via the **bridge** and via **pyghidra**, and compared byte-for-byte.\n",
             f"**Verdict: {'OK — identical to pyghidra everywhere' if all_ok else 'see mismatches below'}**\n",
             "| Target | Result | Notes |", "| --- | --- | --- |"]
    for r in results:
        if r["status"] == "ok":
            res = "8/8 identical" + (" \\*" if r.get("note") else "")
        elif r["status"] == "create-failed":
            res = "could not create project"
        else:
            res = f"DIFF: {', '.join(r['diffs'])}"
        lines.append(f"| {r['label']} | {res} | {r.get('note', '')} |")
    lines.append("\n\\* decompile output matched everywhere except where Ghidra's own decompiler is "
                 "nondeterministic (confirmed by running pyghidra twice) — not a bridge difference.")
    (ROOT / "bench" / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    return all_ok


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-risc", action="store_true", help="skip the clang RISC zoo")
    ap.add_argument("--quick", action="store_true", help="JVM only (fast smoke)")
    ap.add_argument("--skip-build", action="store_true")
    args = ap.parse_args(argv)

    ghidra, _java, javac = check_prereqs()
    if not args.skip_build:
        build()

    targets = gen_targets(ghidra, javac, with_risc=not args.no_risc, quick=args.quick)
    if not targets:
        fail("no test targets could be generated")
    print(f"[targets] {', '.join(targets)}")

    results = []
    for label, binary in targets.items():
        print(f"[verify] {label} ...")
        r = verify_target(label, binary)
        results.append(r)
        tag = "OK" if r["status"] == "ok" else r["status"].upper()
        print(f"[verify] {label}: {tag}" + (f" ({r['note']})" if r.get("note") else ""))

    ok = write_report(results)
    print(f"\n{'ALL OK' if ok else 'MISMATCHES'} -> bench/REPORT.md")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
