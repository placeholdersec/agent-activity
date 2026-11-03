<div align="center">

# Agent Activity

**See what coding agents did on your team's machines.**

[![Tests](https://github.com/placeholdersec/agent-activity/actions/workflows/tests.yml/badge.svg)](https://github.com/placeholdersec/agent-activity/actions/workflows/tests.yml)
[![Security scan](https://github.com/placeholdersec/agent-activity/actions/workflows/security.yml/badge.svg)](https://github.com/placeholdersec/agent-activity/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

<a href="https://www.placeholdersec.com/sample-report"><img src="https://img.shields.io/badge/%E2%96%B6%20%20Explore%20a%20sample%20report-b44c00?style=for-the-badge" alt="Explore a sample report" width="320"></a>

[Very quick start](#very-quick-start) ·
[Quick start](#quick-start) ·
[Team deployment](#team-deployment) ·
[Security and privacy](#security-and-privacy) ·
[Documentation](#documentation)

</div>

Agent Activity reads the Claude Code and Codex session logs on each machine and
builds one self-contained HTML report: the risky commands your agents ran or
attempted, mapped to MITRE ATT&CK, and the code repositories, cloud accounts and
online systems they wrote to.

<p align="center">
  <a href="https://www.placeholdersec.com/sample-report">
    <img src="docs/images/report-systems.png" width="720" alt="A flow from coding agents to the systems they accessed: websites and APIs, SaaS tools via MCP, code repositories, Kubernetes, SSH hosts and cloud providers">
  </a>
</p>

## Highlights

- **No dependencies.** One Python file that uses only the standard library.
- **Runs locally.** It reads logs on the machine and writes one JSON file.
  Nothing is sent anywhere unless you provide an upload link.
- **Private by design.** Prompts, model output and code are not collected.
  Commands appear only as short examples, with secrets masked. See
  [what it reads, writes and sends](docs/privacy.md).
- **Rule-based findings.** Findings come from detection rules applied to the
  commands and tool calls in the logs, not from an AI model.

## What's in the report

1. **Risky actions** the agents ran or attempted, by MITRE ATT&CK tactic and
   severity, with the machines and sessions behind each one.
2. **Systems** the agents accessed, including repositories, cloud accounts,
   clusters, registries and online services, by kind and provider, with which
   ones they wrote to and which they only read.
3. **Other code** the agents started, such as scripts, inline code, builds and
   containers.

The detection rules are derived from open-source rule sets, including Sigma,
shellfirm, panther-analysis and TrailDiscover. The full list of sources is in
[source/rules/NOTICE](source/rules/NOTICE).

## Very quick start

Paste this into Claude Code or Codex:

```text
Clone https://github.com/placeholdersec/agent-activity.git and use it to generate an agent activity report
```

## Quick start

**Requirements:** macOS, Linux or Windows 11; Python 3.9 or later; Claude Code
or Codex logs in your home folder (`~/.claude/projects`, `~/.codex/sessions`; on
Windows, `%USERPROFILE%\.claude\projects`, `%USERPROFILE%\.codex\sessions`).

### macOS and Linux

Clone the repository, collect the activity on this machine, then build the
report:

```sh
git clone https://github.com/placeholdersec/agent-activity.git
cd agent-activity
python3 -I agent-activity.py
python3 -I agent-activity.py report
```

The report opens in your browser and is saved to
`agent-activity-files/agent-activity-report.html`. On a machine without a
desktop, open the file at the path the command prints.

### Windows

In PowerShell, clone the repository, collect the activity on this machine, then
build the report:

```powershell
git clone https://github.com/placeholdersec/agent-activity.git
cd agent-activity
py -3 -I agent-activity.py
py -3 -I agent-activity.py report
```

Run from an administrator PowerShell, it reads every user's logs and saves the
file to `%ProgramData%\AgentActivity`; build the report from there with
`py -3 -I agent-activity.py report $env:ProgramData\AgentActivity`. The
repository also includes `agent-activity.ps1`, which finds a suitable Python
when `py` isn't installed; see [Windows with Intune](docs/mdm.md#windows-with-intune).

## Team deployment

Run the collector on each machine, gather the files in one folder, and build a
single report from them.

- **Managed fleets.** Jamf Pro, Kandji, Intune and Mosyle can run
  `agent-activity.py` as a root script, and Intune can run it as SYSTEM on
  Windows. See the [MDM deployment guide](docs/mdm.md).
- **Your own storage.** Machines can deliver their files to Azure Blob Storage,
  Amazon S3 or Google Cloud Storage that you own. See [Uploading to your own storage](docs/upload.md).
- **By hand.** Ask each developer to run the collector and send you the
  `agent-activity-<name>.json` file it saves:

  ```sh
  git clone https://github.com/placeholdersec/agent-activity.git
  python3 -I agent-activity/agent-activity.py
  ```

Then put the files in one folder and build the report:

```sh
python3 -I agent-activity.py report path/to/folder --org "Your company"
```

To build the report and ask questions about it from Claude Code, see
[Using the Claude Code skill](docs/claude-code.md).

## Usage

### Collect: `agent-activity.py`

Collects activity from the session logs on this machine.

```sh
python3 -I agent-activity.py [--days DAYS] [--out FILE] [--home DIR] [--name NAME] [--upload URL]
```

| Option | Default | Description |
|---|---|---|
| `--days` | `30` | Number of days of logs to read. |
| `--out` | See below | File to write, or `-` for standard output. |
| `--home` | See below | Home folder to read. Can be repeated. |
| `--name` | Serial number | The machine's name in the report. |
| `--upload` | None | HTTPS link to `PUT` the file to; `{name}` becomes the machine's name. See [uploading](docs/upload.md). |

What it reads and where it writes depend on who runs it:

| Run as | Reads | Writes `agent-activity-<name>.json` to |
|---|---|---|
| Your own user | Your logs | `agent-activity-files/` next to the script, or your home folder if that isn't writable |
| Root | Every user's logs, each read as that user | A folder only root can read: `/Library/Application Support/AgentActivity/` on macOS, `/var/lib/agent-activity/` on Linux |
| Administrator or SYSTEM (Windows) | Every user's logs | `%ProgramData%\AgentActivity\`, which only administrators and SYSTEM can read |

### Report: `agent-activity.py report`

Builds the report from a folder of collected files.

```sh
python3 -I agent-activity.py report [FOLDER] [--out FILE] [--org NAME] [--no-sessions]
```

| Option | Default | Description |
|---|---|---|
| `FOLDER` | `agent-activity-files/` | Folder with the collected files. |
| `--out` | See below | HTML report to write. |
| `--org` | None | Organisation name for the report title. |
| `--no-sessions` | Off | Leave per-session records out of the page. |

By default the report is written to `agent-activity-report.html` in the folder.
A `.facts.json` file of the same name is always written next to the report. It
holds the merged numbers behind every figure, and keeps the per-session records
even with `--no-sessions`.

## Security and privacy

- **Your data stays on the machine.** The tool makes no network connection
  unless you set an upload link.
- **Logs are treated as untrusted input.** Log content is assumed to be
  attacker-controlled. Every string is cleaned, length-capped and escaped, and
  the report runs under a strict Content Security Policy that allows only its
  own script, by hash.
- **Nothing to install.** `python3 -I` runs the tool isolated from your Python
  environment, ignoring `PYTHON*` variables, user site-packages and anything in
  the current folder. No virtualenv needed.
- **Least privilege.** As root, the tool reads each user's files as that user.
  It opens only regular files the user owns, never through a link. Output files
  have mode `0600`. On Windows it refuses links and junctions, and its output
  folder is readable only by administrators and SYSTEM.

For full details, see [What it reads, writes and sends](docs/privacy.md). To
report a vulnerability, see [SECURITY.md](SECURITY.md).

### Verify a copy

`agent-activity.py` is generated from `source/`. To confirm that a copy you were
given matches this source, rebuild the script and compare the two files:

```sh
cp /path/to/given/agent-activity.py /tmp/given.py
python3 source/bundle.py
cmp agent-activity.py /tmp/given.py && echo "same"
```

## Documentation

| Guide | Covers |
|---|---|
| [MDM deployment](docs/mdm.md) | Running the collector across a fleet |
| [Uploading to your own storage](docs/upload.md) | Sending files to Azure, Amazon S3 or Google Cloud |
| [What it reads, writes and sends](docs/privacy.md) | Exactly what is collected, and the tool's limits |
| [Using the Claude Code skill](docs/claude-code.md) | Building the report and asking questions from Claude Code |
| [Development](docs/development.md) | Project layout, rebuilding the script and the rules |

## Contributing

Contributions are welcome. Rebuild `agent-activity.py` from `source/`, then run
the tests:

```sh
python3 source/bundle.py
python3 -m unittest discover -s tests
```

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

Agent Activity is licensed under the [Apache License 2.0](LICENSE); see also
[NOTICE](NOTICE). The detection rules are derived from third-party open-source
projects, each under its own licence, as listed in
[source/rules/NOTICE](source/rules/NOTICE).
