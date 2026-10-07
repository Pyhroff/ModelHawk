# ModelHawk Threat Model

## Security objective

Identify code-execution-capable behavior embedded in serialized ML model artifacts without executing the artifact during inspection.

## Assets

- Developer/CI host
- Model loading pipeline
- Credentials and filesystem accessible to the loader
- Integrity of model artifacts

## Attack path

```
Attacker
   │
   ▼
malicious model artifact
   │
   ▼
model registry / download
   │
   ▼
torch.load / pickle.load
   │
   ▼
code execution
```

ModelHawk inserts a static inspection step before the load boundary.

## Threats in scope

- Pickle `GLOBAL` / `STACK_GLOBAL` references to dangerous callables
- `REDUCE`-based execution chains
- Python object-construction gadget indicators
- Unsafe YAML Python tags
- NumPy object-array pickle payloads
- Unsafe model artifacts presented as ordinary ML files

## Security properties

The scanner should:

1. Never deserialize the untrusted artifact.
2. Produce deterministic findings for the same input.
3. Preserve evidence sufficient for manual review.
4. Fail CI at configured severity thresholds.
5. Prefer explicit false-positive tradeoffs over pretending to prove safety.

## Out of scope

- Proving arbitrary native extensions are safe
- Detecting every possible gadget chain
- Runtime sandboxing
- Trustworthiness of the model's learned parameters
- Application-specific behavior after a safe load

## Key limitation

Static opcode analysis is necessarily bounded by the parser and classification model. A SAFE result means only that supported dangerous patterns were not detected.

## Defensive recommendation

Prefer code-free model containers such as safetensors where the deployment stack supports them, and treat untrusted pickle-compatible artifacts as executable content.
