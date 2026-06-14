#!/usr/bin/env python3
"""
ModelHawk - static malware scanner for serialized ML models (a pickle-RCE detector).

WHY THIS EXISTS
    A PyTorch ".pt"/".bin" or a ".pkl" file is not data - it is a program.
    PyTorch saves models with Python's pickle, and unpickling (torch.load /
    pickle.load) *executes* instructions baked into the file. So "I downloaded a
    pretrained model" can mean "I ran a stranger's code as me." This is a real,
    active supply-chain vector (HuggingFace has hosted weaponized models in the
    wild) and the niche that tools like Protect AI's `modelscan`, `picklescan`
    and Trail of Bits' `fickling` exist to cover.

WHAT IT DOES
    Statically disassembles the pickle opcode stream with the stdlib
    `pickletools` and flags the primitives that turn "load a model" into
    "run code": GLOBAL / STACK_GLOBAL imports of dangerous callables
    (os.system, subprocess, builtins.exec, ...) plus the REDUCE / INST / OBJ /
    NEWOBJ opcodes that invoke them. Understands raw pickles, PyTorch zip
    archives (data.pkl inside a .pt), and recognizes the safe `safetensors`
    format.

SAFETY
    ModelHawk only *parses* opcodes - it never deserializes the model, so a
    payload is never invoked. Parsing a pickle does not run it. (Verified by the
    self-test in tests/, which scans live malicious samples and asserts no
    payload fires.)

Stdlib only. MIT-style use. Built as a portfolio project on AI x security
supply chain - pair with make_samples.py to watch it catch an exploit you craft.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from dataclasses import dataclass, field
from io import StringIO

import pickletools  # static opcode parser - does NOT deserialize / execute

__version__ = "1.0.0"

SEVERITY_ORDER = {"SAFE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

# --------------------------------------------------------------------------- #
# Detection tables
# --------------------------------------------------------------------------- #
# Modules with no legitimate place in a serialized model: they grant code,
# process, or filesystem control. Any reference -> CRITICAL.
# Note: os.system serializes as `nt.system` on Windows and `posix.system` on
# Linux, so the whole os/nt/posix family must be covered.
CRITICAL_MODULES = {
    "os", "nt", "posix",
    "subprocess", "pty", "commands",
    "ctypes", "_ctypes",
    "runpy", "webbrowser", "pdb", "bdb", "code", "timeit",
}
# Capability that is occasionally legitimate but a strong red flag in a model.
HIGH_MODULES = {
    "socket", "shutil", "sys", "importlib", "marshal", "multiprocessing",
    "urllib", "urllib2", "http", "httplib", "ftplib", "telnetlib", "smtplib",
    "requests", "asyncio", "_pickle", "cPickle",
}
# Encoding / indirection helpers - commonly used to *hide* a payload.
MEDIUM_MODULES = {
    "base64", "binascii", "zlib", "bz2", "lzma", "gzip", "codecs",
    "tempfile", "glob", "pathlib", "operator", "functools",
}
# Specific callables that are CRITICAL regardless of their module bucket.
CRITICAL_GLOBALS = {
    "builtins.eval", "builtins.exec", "builtins.compile", "builtins.__import__",
    "builtins.getattr", "builtins.setattr", "builtins.open", "builtins.breakpoint",
    "__builtin__.eval", "__builtin__.exec", "__builtin__.execfile",
    "__builtin__.compile", "__builtin__.__import__", "__builtin__.getattr",
    "__builtin__.open", "__builtin__.apply", "__builtin__.file",
    "importlib.import_module", "importlib._bootstrap._load",
    "operator.attrgetter", "operator.methodcaller",
    "code.InteractiveInterpreter", "code.interact",
}
# Globals that are *expected* in legitimate model pickles -> benign (INFO).
BENIGN_GLOBALS = {
    "collections.OrderedDict", "collections.defaultdict", "collections.Counter",
    "builtins.bytearray", "builtins.bytes", "builtins.complex", "builtins.set",
    "builtins.frozenset", "builtins.slice", "builtins.list", "builtins.dict",
    "builtins.tuple", "builtins.int", "builtins.float", "builtins.str",
    "_codecs.encode", "_codecs.decode",
}
# Module prefixes that are normal ML machinery -> INFO (expected, not alarming).
BENIGN_MODULE_PREFIXES = (
    "torch", "numpy", "collections", "sklearn", "pandas", "scipy", "_codecs",
)

# Opcodes that push a string constant (candidate module/qualname for STACK_GLOBAL).
STRING_PUSH_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "STRING", "SHORT_BINSTRING", "BINSTRING",
}
# Opcodes that invoke a callable / build an object - the execution triggers.
TRIGGER_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}

# Pickle protocol signatures (PROTO opcode 0x80 + protocol byte 2..6).
_PROTO_SIGS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05", b"\x80\x06")
_PICKLEISH_NAMES = (".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt",
                    ".data", ".joblib", ".dill", ".model")

MODEL_EXTS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib",
              ".dill", ".model", ".npz", ".safetensors", ".zip"}


def classify_global(module: str, name: str):
    """Return (severity, human-readable reason) for an imported global."""
    full = f"{module}.{name}"
    if full in CRITICAL_GLOBALS:
        return "CRITICAL", f"invokes dangerous callable {full}()"
    if module in CRITICAL_MODULES:
        return "CRITICAL", f"imports {full} from '{module}' (code / process / file execution)"
    if full in BENIGN_GLOBALS:
        return "INFO", f"benign constructor {full}"
    if module in HIGH_MODULES:
        return "HIGH", f"imports {full} from '{module}' (network / io / dynamic import)"
    if module in MEDIUM_MODULES:
        return "MEDIUM", f"imports {full} from '{module}' (often used to obfuscate a payload)"
    for prefix in BENIGN_MODULE_PREFIXES:
        if module == prefix or module.startswith(prefix + "."):
            return "INFO", f"expected ML global {full}"
    return "MEDIUM", f"unrecognized import {full} (manual review recommended)"


@dataclass
class Finding:
    severity: str
    opcode: str
    target: str
    reason: str
    pos: int


@dataclass
class StreamReport:
    label: str
    findings: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    error: str = None
    data: bytes = field(default=None, repr=False)

    @property
    def severity(self) -> str:
        worst = "SAFE"
        for f in self.findings:
            if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]:
                worst = f.severity
        # A pickle that won't fully parse may be obfuscated/truncated -> suspicious.
        if self.error and SEVERITY_ORDER[worst] < SEVERITY_ORDER["MEDIUM"]:
            worst = "MEDIUM"
        return "SAFE" if worst == "INFO" else worst


@dataclass
class FileReport:
    path: str
    verdict: str
    streams: list = field(default_factory=list)
    note: str = None


def scan_pickle_bytes(data: bytes, label: str = "<pickle>") -> StreamReport:
    """Disassemble one pickle stream and flag dangerous opcodes. No execution."""
    findings = []
    counts = {"GLOBAL": 0, "STACK_GLOBAL": 0, "REDUCE": 0, "INST": 0,
              "OBJ": 0, "NEWOBJ": 0, "NEWOBJ_EX": 0, "BUILD": 0}
    recent_strings = []  # rolling buffer to resolve STACK_GLOBAL's (module, qualname)
    error = None
    try:
        for opcode, arg, pos in pickletools.genops(data):
            nm = opcode.name

            if nm in STRING_PUSH_OPS and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 8:
                    recent_strings.pop(0)

            if nm == "GLOBAL":
                counts["GLOBAL"] += 1
                module, _, gname = (arg or "").partition(" ")
                sev, reason = classify_global(module, gname)
                findings.append(Finding(sev, "GLOBAL", f"{module}.{gname}", reason, pos))

            elif nm == "STACK_GLOBAL":
                counts["STACK_GLOBAL"] += 1
                if len(recent_strings) >= 2:
                    module, gname = recent_strings[-2], recent_strings[-1]
                else:
                    module, gname = "<unknown>", "<unknown>"
                sev, reason = classify_global(module, gname)
                findings.append(Finding(sev, "STACK_GLOBAL", f"{module}.{gname}", reason, pos))

            elif nm == "INST" and arg:
                counts["INST"] += 1
                module, _, gname = arg.partition(" ")
                sev, reason = classify_global(module, gname)
                findings.append(Finding(sev, "INST", f"{module}.{gname}", reason, pos))

            elif nm in counts:
                counts[nm] += 1
    except Exception as exc:  # truncated / obfuscated / not actually a pickle
        error = f"{type(exc).__name__}: {exc}"
    return StreamReport(label, findings, counts, error, data)


def _looks_like_pickle(head: bytes) -> bool:
    return head[:2] in _PROTO_SIGS


def _is_safetensors(path: str) -> bool:
    """safetensors = <u64 little-endian header length><JSON header><tensor bytes>."""
    try:
        with open(path, "rb") as f:
            head = f.read(9)
        if len(head) < 9:
            return False
        n = int.from_bytes(head[:8], "little")
        size = os.path.getsize(path)
        return 0 < n < size and head[8:9] == b"{"
    except OSError:
        return False


def iter_pickle_streams(path: str):
    """Yield (label, bytes) for each pickle stream in a file or zip container."""
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    raw = z.read(info)
                    if info.filename.lower().endswith(_PICKLEISH_NAMES) or _looks_like_pickle(raw):
                        yield info.filename, raw
        except zipfile.BadZipFile:
            return
        return
    with open(path, "rb") as f:
        yield "<pickle>", f.read()


def scan_file(path: str) -> FileReport:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".safetensors" or _is_safetensors(path):
        return FileReport(path, "SAFE", [],
                          note="safetensors format - no pickle, no code-execution path")
    streams = [scan_pickle_bytes(data, label) for label, data in iter_pickle_streams(path)]
    if not streams:
        return FileReport(path, "UNKNOWN", [], note="no pickle stream found")
    verdict = "SAFE"
    for s in streams:
        if SEVERITY_ORDER[s.severity] > SEVERITY_ORDER[verdict]:
            verdict = s.severity
    return FileReport(path, verdict, streams)


def gather_paths(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    if os.path.splitext(fn)[1].lower() in MODEL_EXTS:
                        out.append(os.path.join(root, fn))
        elif os.path.isfile(p):
            out.append(p)
        else:
            print(f"warning: path not found: {p}", file=sys.stderr)
    return sorted(out)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
COLORS = {
    "SAFE": "\033[32m", "INFO": "\033[36m", "LOW": "\033[36m", "MEDIUM": "\033[33m",
    "HIGH": "\033[35m", "CRITICAL": "\033[31;1m", "UNKNOWN": "\033[90m",
    "RESET": "\033[0m", "DIM": "\033[2m",
}
ICONS = {
    "SAFE": "[ OK ]", "INFO": "[INFO]", "LOW": "[ LOW]", "MEDIUM": "[WARN]",
    "HIGH": "[HIGH]", "CRITICAL": "[!!!!]", "UNKNOWN": "[ ?? ]",
}


def _enable_windows_ansi():
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _paint(text, sev, use_color):
    if not use_color:
        return text
    return f"{COLORS.get(sev, '')}{text}{COLORS['RESET']}"


def _worst_finding(rep: FileReport):
    worst = None
    for s in rep.streams:
        for f in s.findings:
            if worst is None or SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst.severity]:
                worst = f
    return worst


def _triggers(rep: FileReport):
    trig = set()
    for s in rep.streams:
        for op, c in s.counts.items():
            if c and op in TRIGGER_OPS:
                trig.add(op)
    return trig


def file_headline(rep: FileReport) -> str:
    worst = _worst_finding(rep)
    if worst is None:
        return rep.note or "no findings"
    trig = _triggers(rep)
    if trig and SEVERITY_ORDER[worst.severity] >= SEVERITY_ORDER["HIGH"]:
        return f"{'/'.join(sorted(trig))} -> {worst.target}   ({worst.reason})"
    return worst.reason


def _banner(use_color):
    art = (
        "  __  __         _     _ _  _              _    \n"
        " |  \\/  |___  __| |___| | || |__ ___ __ __| |__ \n"
        " | |\\/| / _ \\/ _` / -_) | __ / _` \\ V  V / / /  \n"
        " |_|  |_\\___/\\__,_\\___|_|_||_\\__,_|\\_/\\_/|_\\_\\  \n"
        "        static pickle-RCE scanner for ML models\n"
    )
    print(_paint(art, "CRITICAL", use_color))


def print_reports(reports, use_color=True, disasm=False, quiet=False):
    for rep in reports:
        flagged = rep.verdict not in ("SAFE", "UNKNOWN")
        if quiet and not flagged:
            continue
        icon = ICONS.get(rep.verdict, "[ ?? ]")
        print(_paint(f"{icon} {rep.verdict:8} {rep.path}", rep.verdict, use_color))
        if flagged:
            print(_paint(f"        |- {file_headline(rep)}", rep.verdict, use_color))
            for s in rep.streams:
                evidence = "  ".join(f"{k}x{v}" for k, v in s.counts.items() if v)
                if evidence:
                    label = "" if s.label == "<pickle>" else f" [{s.label}]"
                    print(_paint(f"           opcodes{label}: {evidence}", "DIM", use_color))
                if s.error:
                    print(_paint(f"           parse error: {s.error}", "DIM", use_color))
            if disasm:
                for s in rep.streams:
                    if s.data is None:
                        continue
                    print(_paint(f"        -- opcode disassembly [{s.label}] --", "DIM", use_color))
                    out = StringIO()
                    try:
                        pickletools.dis(s.data, out)  # static; does not execute
                        print(out.getvalue())
                    except Exception as exc:
                        print(f"           (disasm failed: {exc})")
        elif rep.note:
            print(_paint(f"        |- {rep.note}", rep.verdict, use_color))


def _summary(reports, use_color):
    tally = {}
    for r in reports:
        tally[r.verdict] = tally.get(r.verdict, 0) + 1
    parts = [f"{k}:{v}" for k, v in sorted(tally.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))]
    print(_paint(f"\nscanned {len(reports)} file(s)  ->  " + "  ".join(parts), "DIM", use_color))


def report_to_dict(rep: FileReport):
    return {
        "path": rep.path,
        "verdict": rep.verdict,
        "note": rep.note,
        "streams": [
            {
                "label": s.label,
                "severity": s.severity,
                "error": s.error,
                "counts": {k: v for k, v in s.counts.items() if v},
                "findings": [
                    {"severity": f.severity, "opcode": f.opcode,
                     "target": f.target, "reason": f.reason, "pos": f.pos}
                    for f in s.findings
                ],
            }
            for s in rep.streams
        ],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="modelhawk",
        description="Static scanner for malicious ML model files (pickle RCE). "
                    "Disassembles pickle opcodes - never executes the model.",
    )
    ap.add_argument("paths", nargs="+", help="model file(s) or directory(ies) to scan")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("--disasm", action="store_true",
                    help="print the pickle opcode disassembly for flagged files")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print flagged files")
    ap.add_argument("--fail-on", default="HIGH", choices=list(SEVERITY_ORDER),
                    help="exit non-zero if any file is at/above this severity (default: HIGH)")
    ap.add_argument("--version", action="version", version=f"ModelHawk {__version__}")
    args = ap.parse_args(argv)

    use_color = (not args.no_color) and sys.stdout.isatty() and not args.json
    if use_color:
        _enable_windows_ansi()

    files = gather_paths(args.paths)
    reports = [scan_file(p) for p in files]

    if args.json:
        print(json.dumps([report_to_dict(r) for r in reports], indent=2))
    else:
        if not args.quiet:
            _banner(use_color)
        print_reports(reports, use_color=use_color, disasm=args.disasm, quiet=args.quiet)
        _summary(reports, use_color)

    threshold = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER[r.verdict] for r in reports if r.verdict in SEVERITY_ORDER),
                default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
