# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in Omnodex, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

Email **[security@omnodex.com](mailto:security@omnodex.com)** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected versions, if known
- Any suggested fix, if you have one

We will acknowledge your report within **5 business days** and work with you to understand and address the issue. We aim to provide a fix or mitigation plan within 30 days of confirmation, depending on complexity.

## What qualifies

We are interested in vulnerabilities in the Omnodex software itself, including but not limited to:

- Event log tampering or integrity bypass
- Rule engine bypass (risk events that should fire but don't)
- Credential or sensitive data leakage through Omnodex's own operation
- Interceptor vulnerabilities that could affect the host agent's execution
- Encryption weaknesses in the sync encryptor or key derivation
- Authentication or authorization issues in cloud API interactions

## What does not qualify

- Vulnerabilities in upstream dependencies (report those to the dependency maintainer; if Omnodex is affected, let us know so we can update)
- Issues in AI agents that Omnodex monitors (those are the agent platform's responsibility)
- Social engineering or phishing attacks against Omnodex team members
- Denial of service via resource exhaustion against local CLI tools

## Disclosure

We follow coordinated disclosure. We ask that you give us reasonable time to address the issue before making it public. We will credit reporters in the fix announcement unless you prefer to remain anonymous.

## Supported versions

During the current pre-1.0 development phase, security fixes are applied to the latest release only. We do not backport fixes to older versions at this time.

## Security design

Omnodex is built with several security principles at its core:

- **Zero token overhead.** Interceptors run out-of-band from the agent's context window and never inject content into the agent session.
- **Async by design.** Interceptors append to the event log and exit. They never block the agent's execution path, so a bug in Omnodex cannot stall the monitored agent.
- **Append-only event log.** The JSONL event log is the source of truth. Once written, events are not modified. The SQLite read model is a derived projection that can be rebuilt from the log at any time.
- **End-to-end encrypted sync.** Synced events are encrypted on the machine with AES-256-GCM under a key derived with Argon2id from a passphrase the server never sees. Live events are sealed one at a time with HPKE to the stream's public key. The server stores the stream's private key only wrapped under a separate key derived from the same passphrase, so it cannot unwrap it or decrypt stored events; the browser dashboard derives that key and unwraps it locally.
- **Usage counts.** A machine connected to the hosted dashboard sends two kinds of counts outside the encrypted data: per-rule counts in shadow and guardrails mode (a day, a rule, a kind such as `would_block`, and a number) for rule tuning, and how many tool calls advanced rules checked, for billing. Neither includes tool names, paths, commands, hosts, credentials or conversation content. A machine that is not connected sends neither.
- **Unencrypted metadata.** A connected machine also sends some operational metadata in the clear: its per-platform monitoring state, CLI version, machine label and session IDs. The network edge also sees its IP address.
