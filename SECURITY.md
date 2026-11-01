# Security policy

## Reporting a vulnerability
Email **security@gamai.io** (or info@gamai.io). Do not open a public issue for exploitable problems.
We aim to acknowledge within 72 hours.

## Scope
This repository ships code that may run with elevated trust. We follow least privilege:
- no secrets in the repository, logs, or error messages;
- destructive or irreversible actions must be gated (explicit approval or a deny-list);
- every automated action should be verifiable after the fact (evidence, not assertion).

## Supported versions
The latest release on `main` receives security fixes.

## Out of scope
Findings that require a compromised host, or that only affect unsupported forks.
