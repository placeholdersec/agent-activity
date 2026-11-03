# AGENTS.md

## Creating a report

When asked to create an agent activity report, run the tool from the repository
root. Don't edit any file first. It runs on macOS, Linux and Windows 11.

macOS and Linux:

```sh
python3 -I agent-activity.py
python3 -I agent-activity.py report
```

Windows (PowerShell or Git Bash):

```powershell
py -3 -I agent-activity.py
py -3 -I agent-activity.py report
```

If `py` isn't installed, use `python` instead of `py -3`, but only if it is
Python 3.9 or later from python.org: the `python3` that opens the Microsoft
Store doesn't work.

Run both commands as the user, not with `sudo` or from an administrator
PowerShell: run that way, the tool reads every user's logs and saves the file
elsewhere.

- The first command reads this machine's Claude Code and Codex logs and saves
  one JSON file in `agent-activity-files/`. The second builds
  `agent-activity-files/agent-activity-report.html` and opens it.
- Python 3.9 or later is all it needs. Don't install packages or create a
  virtual environment.
- Don't pass `--upload` and don't send the JSON file or the report anywhere.
  Both stay on this machine unless the user asks otherwise.
- Then tell the user where the report is, and sum it up in a few lines from
  `agent-activity-files/agent-activity-report.facts.json`: risky actions,
  write operations to shared systems, and the share of commands that started
  other code. Say "ran or tried": the logs don't record whether a command
  worked.

## Changing the code

Edit `source/`, never `agent-activity.py` directly, then rebuild and test:

```sh
python3 source/bundle.py
cd tests && python3 -m unittest discover
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/privacy.md](docs/privacy.md).
