# EntropyLab repository instructions for coding assistants

Before security, key-handling or release work, read [AGENTS.md](../AGENTS.md), [the security posture](../docs/SECURITY_POSTURE.md) (the evidence map and the known limits), [the threat model](../docs/Threat_Model.md) and [SECURITY.md](../SECURITY.md).

- **Check the code, not the docs alone.** Read the code, tests and pull request status at the commit you are on. `rock` is the development line; a pending pull request is not shipped behaviour.
- **Keep the design's rules.** EntropyLab converts entropy the user supplies. Never add generated key entropy, network access, runtime dependencies or storage the user didn't ask for, and keep the output one self-contained `entropylab.html`.
- **Back every security claim.** Link it to the code or test behind it. Keep the limits accurate: the in-app clipboard covers the app's private copy controls, memory clearing is best effort, and the Journal password is optional.
- **Follow the [contribution rules](../CONTRIBUTING.md):** small focused changes, a regression test that fails without the fix, and no edits to generated artifacts.
