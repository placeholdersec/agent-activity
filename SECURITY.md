# Security policy

## Supported versions

Only the latest version of `agent-activity.py` receives security fixes. Each
collected file records the version that wrote it under `collector.version`.

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately in
either of these ways:

- Email security@placeholdersec.com.
- On GitHub, go to **Security > Report a vulnerability** on this repository.

Include what you found, how to reproduce it and the impact you expect. A minimal
log file or command is ideal. Don't include real session logs, because they can
contain your own prompts and secrets.

We aim to acknowledge reports within 3 business days and to agree on a fix and
disclosure date with you. We credit reporters who want to be named.

## Scope

**In scope:**

- `agent-activity.py` and everything in `source/`, including log reading, the
  collected file, the upload, the report and its facts file.
- Anything that lets log content run code, change the report's page script,
  reach the network, or leave behind data that
  [the documentation](docs/privacy.md) says is never kept.

**Out of scope:**

- Findings that require an attacker who already controls the user's account or
  root on the machine.
- Detection gaps, meaning risky commands the rules don't flag. Please open a
  regular issue for these.

## Threat model

- **Session logs are attacker-influenced.** A malicious repository or web page
  can steer an agent into running commands with arbitrary text. That text
  reaches the collected file and the report, so it is cleaned, length-capped and
  escaped everywhere, and the report page allows only its own script, by hash.
- **Root access is limited.** Run as root, the collector reads each user's files
  as that user. It opens only regular files they own, never through a link, and
  writes only to a folder that only root can read.
- **Network access is opt-in.** The tool makes no network connection unless an
  upload link is set. With a link, it sends only the collected file, in one HTTPS
  `PUT`, without following redirects.
