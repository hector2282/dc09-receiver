# Security policy

dc09-receiver sits on an internet-facing port and its output can trigger
real-world responses (guards, police dispatch), so we take reports seriously.

## Supported versions

The latest released minor version receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability
reporting ("Security" tab, "Report a vulnerability") on this repository.

Include the affected version, a description, and a proof of concept if possible
(a crafted frame is ideal). We aim to acknowledge within 5 business days and to
publish a fix and advisory within 90 days, crediting you unless you prefer otherwise.

## Scope

In scope: crashes or hangs caused by crafted input, memory/CPU exhaustion, ACKs
that make a panel believe an event was accepted when it was not, decryption or
authentication flaws, webhook signature issues.

Out of scope: weaknesses of the DC-09 standard itself (e.g. spoofing of
unencrypted messages, which is documented in the README), and deployments that
expose the port without encryption against that advice.

## Hardening checklist

- Expose only the DC-09 port; run the container as the provided non-root user.
- Use AES keys per account and `accept_unknown_accounts = false` in production.
- Keep keys and webhook secrets in environment variables or a secret store, never in the config file in git.
