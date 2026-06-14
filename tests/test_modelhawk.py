#!/usr/bin/env python3
"""
Self-test for ModelHawk.

Proves three things that matter:
  1. Detection works on BOTH pickle opcode paths - protocol 2 (inline GLOBAL)
     and protocol 5 (STACK_GLOBAL) - plus inside a PyTorch zip wrapper.
  2. Benign and safetensors files are NOT false-flagged.
  3. SAFETY: scanning never executes a payload (no PWNED.txt is ever created),
     and the scanner source contains no unpickling calls.

Run directly:
    python tests/test_modelhawk.py
or with pytest:
    pytest tests/
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import make_samples
import modelhawk


def _scan_dir(d):
    return {os.path.basename(r.path): r
            for r in (modelhawk.scan_file(p) for p in modelhawk.gather_paths([d]))}


def test_detection_and_no_false_positives():
    with tempfile.TemporaryDirectory() as d:
        samples = os.path.join(d, "samples")
        make_samples.build_samples(samples)
        reports = _scan_dir(samples)

        assert reports, "no files were scanned"
        for name, rep in reports.items():
            if name.startswith("malicious"):
                assert rep.verdict == "CRITICAL", f"{name} should be CRITICAL, got {rep.verdict}"
            elif name.startswith("benign"):
                assert rep.verdict == "SAFE", f"{name} should be SAFE, got {rep.verdict}"
            elif name.endswith(".safetensors"):
                assert rep.verdict == "SAFE", f"{name} should be SAFE, got {rep.verdict}"

        # Both protocols must independently trip the scanner.
        assert reports["malicious_os_system.p2.pkl"].verdict == "CRITICAL"
        assert reports["malicious_os_system.p5.pkl"].verdict == "CRITICAL"
        assert reports["malicious_exec.p2.pkl"].verdict == "CRITICAL"
        assert reports["malicious_exec.p5.pkl"].verdict == "CRITICAL"
        # The zip-wrapped .pt must be unwrapped and flagged.
        assert reports["malicious_pytorch_model.pt"].verdict == "CRITICAL"


def test_scanning_never_detonates_payload():
    with tempfile.TemporaryDirectory() as d:
        cwd = os.getcwd()
        os.chdir(d)  # payloads (if they ran) would drop PWNED.txt under cwd
        try:
            samples = os.path.join(d, "samples")
            make_samples.build_samples(samples)
            for p in modelhawk.gather_paths([samples]):
                modelhawk.scan_file(p)
            stray = []
            for root, _dirs, files in os.walk(d):
                stray += [f for f in files if f == make_samples.MARKER]
            assert not stray, f"scanner detonated a payload! found {stray}"
        finally:
            os.chdir(cwd)


def test_scanner_contains_no_unpickling_calls():
    """AST-level invariant: the scanner never imports `pickle` or calls
    load / loads / Unpickler. We inspect the parse tree, not raw text, so
    mentions in docstrings or comments don't count - only real code does."""
    import ast

    src = pathlib.Path(modelhawk.__file__).read_text(encoding="utf-8")
    bad = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in ("pickle", "cPickle", "_pickle"):
                    bad.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in ("pickle", "cPickle", "_pickle"):
                bad.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Attribute):
            if (node.attr in ("load", "loads")
                    and isinstance(node.value, ast.Name)
                    and node.value.id in ("pickle", "cPickle", "_pickle")):
                bad.append(f"{node.value.id}.{node.attr}()")
        elif isinstance(node, ast.Name) and node.id == "Unpickler":
            bad.append("Unpickler")
    assert not bad, f"scanner must never deserialize; found {bad}"


def test_classify_global_severity_table():
    """Lock in the severity mapping the README advertises - including the
    benign-ML-prefix and 'unrecognized import' branches that the sample corpus
    alone never exercises (real models hit exactly these paths)."""
    cases = {
        # expected ML machinery -> INFO (benign)
        ("torch._utils", "_rebuild_tensor_v2"): "INFO",
        ("numpy.core.multiarray", "_reconstruct"): "INFO",
        ("collections", "OrderedDict"): "INFO",
        # code / process execution -> CRITICAL (os family, subprocess, builtins,
        # and the protocol-2 '__builtin__' legacy name)
        ("nt", "system"): "CRITICAL",
        ("posix", "system"): "CRITICAL",
        ("subprocess", "Popen"): "CRITICAL",
        ("builtins", "eval"): "CRITICAL",
        ("__builtin__", "exec"): "CRITICAL",
        # network / dynamic-import capability -> HIGH
        ("socket", "socket"): "HIGH",
        # unknown third-party import -> MEDIUM (manual review, does not fail CI)
        ("some_random_pkg", "Thing"): "MEDIUM",
    }
    for (module, name), expected in cases.items():
        sev, _reason = modelhawk.classify_global(module, name)
        assert sev == expected, f"{module}.{name}: expected {expected}, got {sev}"


if __name__ == "__main__":
    tests = [
        test_detection_and_no_false_positives,
        test_scanning_never_detonates_payload,
        test_scanner_contains_no_unpickling_calls,
        test_classify_global_severity_table,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
