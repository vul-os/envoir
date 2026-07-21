# Security Policy

Envoir is the reference implementation of DMTAP — sovereign, metadata-private messaging where your key is your identity. Security reports are taken seriously and handled with priority.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Preferred: [GitHub private vulnerability reporting](https://github.com/vul-os/envoir/security/advisories/new) on `vul-os/envoir`.
- Alternatively, email **vulosorg@gmail.com** with `[envoir security]` in the subject.

You will get an acknowledgement within **72 hours** and a status update at least every **14 days** until resolution. Please allow a reasonable window to ship a fix before public disclosure.

## Scope

- **Identity & key handling** — any path that leaks, mishandles or lets another party impersonate a keypair identity.\n- **Crypto** — flaws in the MLS/X3DH/HPKE usage, sealed-sender, or the mesh/mixnet metadata-privacy guarantees.\n- **Transport-path provenance** — claiming more anonymity than a tier provides.\n- **Legacy gateway** — leaks across the DMTAP↔SMTP boundary.

Out of scope: vulnerabilities requiring an already-compromised host, and issues in third-party services the operator configures.

## Supported versions

Pre-1.0: only the latest release (and `main`) receives fixes.
