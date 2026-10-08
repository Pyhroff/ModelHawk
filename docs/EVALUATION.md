# ModelHawk Evaluation Methodology

## Evaluation objective

Demonstrate that ModelHawk catches supported malicious serialization patterns while avoiding execution of the inspected payload and limiting false positives on benign model artifacts.

## Test matrix

At minimum, evaluate:

| Category | Positive cases | Negative cases |
|---|---|---|
| Pickle protocol | 2, 4, 5 | benign state dicts |
| Global resolution | `os/nt/posix`, `subprocess`, builtins execution | normal ML globals |
| Invocation | `REDUCE`, object construction paths | non-executing opcode sequences |
| Containers | raw pickle, PyTorch ZIP | safetensors |
| Configuration | YAML Python tags | ordinary YAML |
| Arrays | object-array pickle | numeric NumPy arrays |

## Safety invariant

The scanner must not call `pickle.load`, `pickle.loads`, `Unpickler`, or an equivalent deserializer on the inspected bytes.

This invariant should be tested structurally as well as behaviorally.

## Metrics

For a labeled corpus report:

- TP / FP / TN / FN
- precision, recall and F1
- false-positive rate
- severity distribution
- scan time by artifact type

Security claims should include corpus size and exact artifact-generation method.

## Reproducibility

Record:

- ModelHawk commit/version
- Python version
- operating system
- corpus revision
- scanner flags
- artifact hashes

The malicious fixtures should remain harmless and deterministic. Tests should prove that scanning them does not create their payload side effects.

## Research questions

Useful future experiments include:

1. How much coverage improves with a complete pickle stack-machine model?
2. Which gadget families remain invisible under a module allowlist?
3. What is the false-positive cost of expanding coverage?
4. How does static analysis compare with sandboxed dynamic loading for detection coverage?
