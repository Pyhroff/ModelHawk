# ModelHawk

**A static malware scanner for serialized ML models — it detects code-execution backdoors hidden inside PyTorch / pickle model files *without* running them.**

> A `.pt` / `.bin` / `.pkl` model file is not data — it's a program. ModelHawk reads the program and tells you if it bites.



---

## The 30-second pitch

PyTorch saves models with Python's **`pickle`**, and *unpickling* a file (`torch.load()` / `pickle.load()`) **executes instructions baked into it**. So "I downloaded a pretrained model from HuggingFace" can quietly mean *"I ran a stranger's code as me."* This is a real, active **AI supply-chain** attack vector — malicious models have been found hosted on public hubs in the wild — and it's the niche that tools like [`picklescan`](https://github.com/mmaitre314/picklescan), Protect AI's [`modelscan`](https://github.com/protectai/modelscan), and Trail of Bits' [`fickling`](https://github.com/trailofbits/fickling) exist to cover.

**ModelHawk** is a clean, dependency-free implementation of that idea, built end to end:

- 🦅 **The scanner** — statically disassembles the pickle opcode stream and flags the primitives that turn *load* into *execute*.
- 💣 **The offensive half** (`make_samples.py`) — crafts a real (but harmless) malicious model so you can watch the scanner catch an exploit chain *you* authored.
- 🧪 **A self-test** that proves detection works on both pickle encodings **and** that scanning never detonates a payload.

Stdlib only. No `torch`, no `numpy`, no network, no install.

---

## How the attack works

Pickle is a tiny stack VM. During a load it can import any global and call it. The classic delivery is the `__reduce__` hook — whatever `(callable, args)` tuple it returns gets **executed** on load:

```python
class Payload:
    def __reduce__(self):
        import os
        return (os.system, ("whoami",))     # runs the instant someone load()s this
```

Pickle that object into a `.pkl` (or drop it inside a `.pt` zip as `data.pkl`) and ship it. The victim doesn't run anything "suspicious" — they just **load a model**.

> Building the file is safe: `pickle.dumps` only *records* the `(callable, args)` tuple — it never invokes the callable. Execution happens only on **load**. ModelHawk exploits exactly this asymmetry: it inspects the recorded opcodes and never loads.

---

## What ModelHawk looks at

It walks the opcode stream with the stdlib **`pickletools`** (a pure parser — no deserialization) and flags:

| Opcode | Meaning | Why it matters |
|---|---|---|
| `GLOBAL` (proto ≤3) | import `module.name` (inline) | how `os.system` / `builtins.exec` get referenced |
| `STACK_GLOBAL` (proto ≥4) | import `module.name` (from stack) | same, but module+name arrive as two preceding strings |
| `REDUCE` | call `callable(*args)` | **the trigger** that actually executes the import |
| `INST` / `OBJ` / `NEWOBJ` / `BUILD` | build an object / run `__setstate__` | alternate execution / gadget paths |

Each imported global is scored by a **severity table** (full lists in `modelhawk.py`):

- **CRITICAL** — `os` / `nt` / `posix`, `subprocess`, `builtins.exec|eval|compile|__import__`, `ctypes`, `runpy`, `pty`, `code.InteractiveInterpreter`, …
- **HIGH** — `socket`, `shutil`, `importlib`, `marshal`, `urllib`/`requests` (network exfil), nested `_pickle`, …
- **MEDIUM** — `base64`/`zlib`/`codecs` (payload obfuscation), or any *unrecognized* import → "manual review."
- **INFO / SAFE** — expected ML machinery (`collections.OrderedDict`, `torch.*`, `numpy.*` rebuild functions).

> **Design note — low false positives by construction.** Real models routinely pickle references to their *own* custom classes (`GLOBAL mymodel MyNet`). Those land as **MEDIUM "manual review,"** and because the CI gate defaults to `--fail-on HIGH`, legitimate models with custom classes **pass cleanly** — you get the signal without the false alarm. Only genuine code-execution sinks (`os`/`subprocess`/`builtins.exec`/…) reach CRITICAL and fail the build.

### Two subtleties that bite people who reason from memory

ModelHawk handles both because they were verified empirically, not assumed:

1. **`os.system` is `nt.system`.** On Windows, `pickle.dumps(os.system)` serializes the module as **`nt`** (`posix` on Linux) — the OS backend, not `os`. A denylist that only knows `os` misses every Windows-built payload. ModelHawk covers the whole `os`/`nt`/`posix` family.
2. **`exec` changes name by protocol.** Protocol 2 emits **`__builtin__.exec`** (the Python-2 module name, kept for back-compat); protocol 5 emits **`builtins.exec`**. The demo below shows both — and both are flagged.

---

## Quickstart

```bash
# 1) See the whole story (craft samples -> scan -> disassemble one):
python demo.py

# 2) Scan a directory of real models (recurses, picks model extensions):
python modelhawk.py ~/Downloads/models/

# 3) CI gate — non-zero exit if anything is HIGH or worse:
python modelhawk.py model.pt --fail-on HIGH ; echo "exit=$?"

# 4) Machine-readable:
python modelhawk.py model.pt --json
```

Useful flags: `--disasm` (full opcode dump for flagged files), `--json`, `--quiet` (only flagged files), `--fail-on {SAFE..CRITICAL}`, `--no-color`.

---

## Example output

Scanning the crafted corpus (`python demo.py`):

```
[ OK ] SAFE     samples/benign_state_dict.pkl
[!!!!] CRITICAL samples/malicious_exec.p2.pkl
        |- REDUCE -> __builtin__.exec   (invokes dangerous callable __builtin__.exec())
           opcodes: GLOBALx1  REDUCEx1
[!!!!] CRITICAL samples/malicious_exec.p5.pkl
        |- REDUCE -> builtins.exec   (invokes dangerous callable builtins.exec())
           opcodes: STACK_GLOBALx1  REDUCEx1
[!!!!] CRITICAL samples/malicious_os_system.p2.pkl
        |- REDUCE -> nt.system   (imports nt.system from 'nt' (code / process / file execution))
           opcodes: GLOBALx1  REDUCEx1
[!!!!] CRITICAL samples/malicious_os_system.p5.pkl
        |- REDUCE -> nt.system   (imports nt.system from 'nt' (code / process / file execution))
           opcodes: STACK_GLOBALx1  REDUCEx1
[!!!!] CRITICAL samples/malicious_pytorch_model.pt
        |- REDUCE -> nt.system   (imports nt.system from 'nt' (code / process / file execution))
           opcodes [archive/data.pkl]: GLOBALx1  REDUCEx1
[ OK ] SAFE     samples/safe_model.safetensors
        |- safetensors format - no pickle, no code-execution path

scanned 7 file(s)  ->  CRITICAL:5  SAFE:2
```

The `--disasm` view of one malicious sample — the smoking gun, opcode by opcode:

```
    0: \x80 PROTO      2
    2: c    GLOBAL     'nt system'      <-- import os.system (as nt.system on Windows)
   15: X    BINUNICODE 'echo You just executed code hidden in an ML model. > PWNED.txt'
   84: \x85 TUPLE1                      <-- build the (cmd,) argument tuple
   87: R    REDUCE                      <-- CALL nt.system(cmd)  == code execution on load
   90: .    STOP
```

---

## Safety design

- The scanner **never deserializes** a model. It uses only `pickletools.genops` / `pickletools.dis`, which *parse* opcodes — they never construct objects or invoke `__reduce__`. Inspecting a malicious pickle is safe.
- This is enforced by a test (`test_scanner_contains_no_unpickling_calls`) that walks the scanner's **AST** and fails the build if anyone ever adds an `import pickle`, a `.load()/.loads()`, or an `Unpickler`.
- The bundled "malicious" samples are harmless by construction — their payload only writes a `PWNED.txt` marker; no deletion, persistence, or network. A test scans them from a temp directory and asserts no marker is ever created — i.e. the scanner inspects an exploit **without firing it**.

```
$ python tests/test_modelhawk.py
PASS  test_detection_and_no_false_positives        # both protocols + the .pt zip
PASS  test_scanning_never_detonates_payload        # no PWNED.txt after scanning
PASS  test_scanner_contains_no_unpickling_calls    # AST invariant
PASS  test_classify_global_severity_table          # severity table / false-positive path
4/4 passed
```

---

## The fix: `safetensors`

The root cause is that pickle is Turing-complete *by design*. The industry fix is [**safetensors**](https://github.com/huggingface/safetensors): a dumb, code-free container — an 8-byte length, a JSON header of tensor shapes/offsets, then raw bytes. There is no `__reduce__`, no opcode VM, **no code path**. ModelHawk recognizes it and reports `SAFE`. **Prefer `safetensors`; treat `.pkl`/`.pt`/`.bin` from untrusted sources as code.**

---

## Project layout

```
ModelHawk/
├─ modelhawk.py            # the scanner (importable library + CLI)
├─ make_samples.py         # offensive half: crafts harmless malicious samples
├─ demo.py                 # craft -> scan -> disassemble, in one command
├─ tests/test_modelhawk.py # self-test (both protocols, no-detonation, AST invariant)
├─ README.md
└─ LICENSE                 # MIT
```

## Limitations & future work (honest scope)

- `STACK_GLOBAL` resolution uses a **recent-strings heuristic** (the last two pushed strings), the same pragmatic approach `picklescan` takes — not a full pickle stack-machine. Adversarial opcode reordering could evade it; a complete VM is the natural next step.
- `torch.*` / `numpy.*` are trusted as benign machinery to keep false positives low. A determined attacker abusing a gadget *inside* an allowlisted module wouldn't be flagged — gadget-chain analysis is future work.
- Container coverage is `.pkl` + PyTorch `.zip`/`.pt` + `safetensors`. `.npy`/`.npz` object arrays, `joblib`, and `dill` extensions are recognized as model files but not yet deeply parsed.

## References

- CWE-502: Deserialization of Untrusted Data
- Python docs — *"the pickle module is not secure; only unpickle data you trust."*
- HuggingFace **safetensors** (the safe format) · Protect AI **modelscan** · Trail of Bits **fickling** · **picklescan**

## License

Released under the [MIT License](LICENSE).

---

*Built as a portfolio project on AI × security supply chain. Author: Pyhroff.*
