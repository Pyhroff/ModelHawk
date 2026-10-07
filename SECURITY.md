# Security Policy

## Scope

ModelHawk is a static security scanner for serialized ML and model-adjacent files. Security reports are welcome for scanner parsing, unsafe deserialization detection, report generation, dependency/workflow configuration, and any path that could cause ModelHawk itself to execute untrusted input.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting or security advisory mechanism for this repository when available. Include:

- A concise description and security impact.
- The affected file, function, workflow, or dependency.
- Reproduction steps or a minimal proof of concept.
- Logs or screenshots with credentials and personal data removed.
- A proposed mitigation if known.

Do not submit real credentials, private model files, or unauthorized target data.

## Responsible disclosure

Give maintainers reasonable time to investigate and address the issue before public disclosure. Do not use the scanner to access, modify, or exfiltrate data you are not authorized to handle.

## Security expectations

ModelHawk is intentionally designed so the scanner does not deserialize model input. Changes that introduce `pickle.load`, `pickle.loads`, `Unpickler`, or equivalent execution paths should be treated as security-sensitive and must preserve the AST-level no-unpickling test.

Users should still treat scan results as static-analysis evidence rather than a guarantee of model safety. Keep ModelHawk updated and use safer model formats such as safetensors where practical.

## Supported versions

Only the latest commit on the default `main` branch is actively maintained for security fixes.
