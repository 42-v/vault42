# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vault42, **please report it responsibly**. Do not open a public GitHub issue.

**Email:** vault@42-v.com

Hosted on Tuta (end-to-end encrypted). If you prefer, you can encrypt your report — reach out for a public key.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response timeline

- **Acknowledgment:** within 48 hours
- **Assessment:** within 7 days
- **Fix or mitigation:** as soon as reasonably possible

### What qualifies

- Authentication or authorization bypasses
- Token forgery or manipulation
- Cryptographic weaknesses
- Injection vulnerabilities (SQL, XSS, command)
- Information disclosure (user enumeration, timing leaks)
- Privilege escalation

### What does not qualify

- Denial of service (this is a single-origin service, not a public API)
- Issues in dependencies — report those upstream, but feel free to let me know
- Vulnerabilities that require physical access to the server
- Social engineering

## Supported Versions

Only the latest release on `main` is supported. There are no LTS branches.

## Disclaimer

Vault42 is designed with security as a core principle, but **it is only as secure as the system it is deployed on**. No software can compensate for misconfigured infrastructure, leaked secrets, or unpatched systems. You are responsible for securing your own deployment.
