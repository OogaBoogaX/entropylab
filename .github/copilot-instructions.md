# EntropyLab repository instructions for coding assistants

Before making security, key-handling, or release claims, read [AGENTS.md](../AGENTS.md), [the security posture](../docs/SECURITY_POSTURE.md), [the threat model](../docs/Threat_Model.md), and [SECURITY.md](../SECURITY.md).

- Treat `rock` as a development branch. Read actual code, current tests, and PR status before describing behavior as shipped.
- EntropyLab converts **operator-supplied** entropy; never introduce automatic key entropy, network egress, runtime dependencies, or uncontrolled persistence.
- Distinguish **private in-app clipboard** operations from **public OS clipboard** operations. Private readout copy controls do not use the OS clipboard; editable fields and host software are separate risks.
- Journal recovery exports include sensitive material. Their AES-256-GCM protection is password-optional and deterministic; never call a passwordless export confidential.
- Byte-buffer/WASM wipes are best-effort. Do not promise erasure of immutable strings or OS/browser-managed copies.
- Do not claim EntropyLab is "the safest," "unhackable," or independently certified; link every security assertion to code, tests, and documented scope.
- Follow the existing [contribution rules](../CONTRIBUTING.md): small focused changes, behavioral regression tests, and no edits to generated artifacts.
