# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-31

### Security

- The collected file no longer holds login names or host names.

### Changed

- The script's header shows `python3 -I agent-activity.py`, like the README;
  `sh agent-activity.py` still works.
- The MDM and upload guides note that editing `UPLOAD_URL` changes the file's
  checksum, and suggest Jamf parameter 4 or `--upload` instead.
- Releases before 1.0 are published as pre-releases.

### Fixed

- The tests run on Linux images without `/usr/bin/python3`, and CI tests
  Python 3.9 on Linux.

## [0.1.0] - 2026-10-30

### Added

- A collector for Claude Code and Codex session logs on macOS and Linux. It
  maps the commands agents ran or tried, the MCP tools they called and the pages
  they opened to findings by MITRE ATT&CK tactic and risk, the systems they read
  or changed (code repositories, cloud accounts, clusters, registries, web hosts,
  SaaS tools via MCP, SSH hosts), and the commands that started other code.
- An organisation report from the collected files, as one self-contained HTML
  page: risky actions by tactic and machine, changes by kind of system and
  provider, the systems accessed or changed, and the commands agent policies
  can't check, with side panels down to each action and each session.
- Per-session records with salted ids, for the drill-down from an action to the
  sessions it happened in.
- Privacy by design: no prompts, model output, code, file contents, paths, user
  names or host names are collected; commands are kept only as short examples
  with secrets masked; nothing is sent unless an upload link is set.
- One file, `agent-activity.py`, built reproducibly from `source/`, with no
  dependencies beyond the Python 3.9+ standard library.

[0.1.1]: https://github.com/placeholdersec/agent-activity/releases/tag/v0.1.1
[0.1.0]: https://github.com/placeholdersec/agent-activity/releases/tag/v0.1.0
