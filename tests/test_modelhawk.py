#!/usr/bin/env python3
"""
Self-test for ModelHawk.

Proves:
  1. Detection works on ALL supported attack vectors:
     - Pickle RCE (protocols 2 and 5, raw and zip-wrapped .pt)
     - Unsafe YAML (!!python/object/apply and friends)
     - Numpy object arrays (hand-crafted .npy + real numpy if available)
  2. Benign and safetensors files are NOT false-flagged.
  3. SAFETY: scanning never executes a payload (no PWNED.txt is ever created),
     and the scanner source contains no unpickling calls.

Run directly:
    python tests/test_modelhawk.py
or with pytest:
    pytest tests/
"""
import ast
import os
import pathlib
import pickle
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

        # Pickle: both protocols must independently trip the scanner.
        assert reports["malicious_os_system.p2.pkl"].verdict == "CRITICAL"
        assert reports["malicious_os_system.p5.pkl"].verdict == "CRITICAL"
        assert reports["malicious_exec.p2.pkl"].verdict == "CRITICAL"
        assert reports["malicious_exec.p5.pkl"].verdict == "CRITICAL"
        # The zip-wrapped .pt must be unwrapped and flagged.
        assert reports["malicious_pytorch_model.pt"].verdict == "CRITICAL"
        # YAML attack vector.
        assert reports["malicious_config.yaml"].verdict == "CRITICAL"
        assert reports["benign_config.yaml"].verdict == "SAFE"
        # Numpy object-array attack vector.
        assert reports["malicious_object_array.npy"].verdict == "CRITICAL"
        assert reports["benign_float_array.npy"].verdict == "SAFE"


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
    """AST-level invariant: the scanner never imports pickle or calls load/loads/Unpickler."""
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
    """Lock in the severity mapping the README advertises."""
    cases = {
        ("torch._utils", "_rebuild_tensor_v2"): "INFO",
        ("numpy.core.multiarray", "_reconstruct"): "INFO",
        ("collections", "OrderedDict"): "INFO",
        ("nt", "system"): "CRITICAL",
        ("posix", "system"): "CRITICAL",
        ("subprocess", "Popen"): "CRITICAL",
        ("builtins", "eval"): "CRITICAL",
        ("__builtin__", "exec"): "CRITICAL",
        ("socket", "socket"): "HIGH",
        ("some_random_pkg", "Thing"): "MEDIUM",
    }
    for (module, name), expected in cases.items():
        sev, _reason = modelhawk.classify_global(module, name)
        assert sev == expected, f"{module}.{name}: expected {expected}, got {sev}"


def test_yaml_detection():
    """YAML scanning catches all dangerous PyYAML tags and ignores benign YAML."""
    cases_critical = [
        b"payload: !!python/object/apply:os.system ['echo pwned']\n",
        b"x: !!python/object/new:subprocess.Popen\n  - ['sh', '-c', 'id']\n",
    ]
    cases_high = [
        b"obj: !!python/object:os.stat_result {}\n",
        b"mod: !!python/module:os\n",
    ]
    cases_safe = [
        b"model:\n  layers: 10\n  lr: 0.001\n",
        b"# just a comment\nname: resnet50\n",
        b"",
    ]
    for data in cases_critical:
        stream = modelhawk.scan_yaml_bytes(data)
        assert stream.severity == "CRITICAL", f"expected CRITICAL for {data!r}, got {stream.severity}"
    for data in cases_high:
        stream = modelhawk.scan_yaml_bytes(data)
        assert stream.severity == "HIGH", f"expected HIGH for {data!r}, got {stream.severity}"
    for data in cases_safe:
        stream = modelhawk.scan_yaml_bytes(data)
        assert stream.severity == "SAFE", f"expected SAFE for {data!r}, got {stream.severity}"


def test_npy_object_array_handcrafted():
    """Hand-crafted .npy with malicious pickle payload must be CRITICAL (no numpy needed)."""
    class _Payload:
        def __reduce__(self):
            import os as _os
            return (_os.system, ("echo pwned",))

    pkl = pickle.dumps([_Payload()], protocol=3)
    npy_data = make_samples._make_npy_bytes(pkl)
    stream = modelhawk.scan_npy_bytes(npy_data)
    assert stream.severity == "CRITICAL", f"expected CRITICAL, got {stream.severity}"


def test_npy_float_array_safe():
    """Non-object .npy (numeric dtype) must be SAFE — no pickle, no risk."""
    npy_data = make_samples._make_benign_npy_bytes()
    stream = modelhawk.scan_npy_bytes(npy_data)
    assert stream.severity == "SAFE", f"expected SAFE, got {stream.severity}"


def test_npy_real_numpy_object_array():
    """Use real numpy (if installed) to write a malicious object array and detect it."""
    try:
        import numpy as np
    except ImportError:
        print("SKIP  test_npy_real_numpy_object_array (numpy not installed)")
        return

    class _RealPayload:
        def __reduce__(self):
            import os as _os
            return (_os.system, ("echo pwned",))

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "model_data.npy")
        arr = np.array([_RealPayload()], dtype=object)
        np.save(path, arr, allow_pickle=True)
        rep = modelhawk.scan_file(path)
        assert rep.verdict == "CRITICAL", (
            f"real numpy object array not flagged — got {rep.verdict}. "
            f"Findings: {[f.target for s in rep.streams for f in s.findings]}"
        )


if __name__ == "__main__":
    tests = [
        test_detection_and_no_false_positives,
        test_scanning_never_detonates_payload,
        test_scanner_contains_no_unpickling_calls,
        test_classify_global_severity_table,
        test_yaml_detection,
        test_npy_object_array_handcrafted,
        test_npy_float_array_safe,
        test_npy_real_numpy_object_array,
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
