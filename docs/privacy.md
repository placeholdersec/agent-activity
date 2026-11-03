# What it reads, writes and sends

Agent Activity is designed to collect as little as possible. This page lists
everything it reads, everything it writes and the only data that can leave the
machine.

**In short:** prompts, model output, code, file contents and credentials are
never written to the collected file. Commands appear only as short examples
with secrets masked, and nothing is sent unless you set an upload link.

## What it reads

The tool reads files per user, as that user. It opens only regular files the
user owns inside their home folder, and never follows a link to reach them.
On Windows, where `~` is the user's profile folder (`C:\Users\<name>`), it
also refuses junctions and checks that the file it opened is the one it
checked; there it doesn't compare owners, since access is set by ACLs.

### Claude Code

- `~/.claude/projects/**/*.jsonl`: the session logs.

### Codex

- `~/.codex/sessions/**/rollout-*.jsonl` and
  `~/.codex/archived_sessions/rollout-*.jsonl`: the session logs.

From these logs, the tool takes:

- The commands Codex ran, including those in a code mode script
- The MCP tools it called: the server, the tool and, for a SQL tool, whether the
  call writes
- The pages it opened
- Which tools it used
- The session's start, end, version and folder

It keeps the account IDs found in the output of AWS commands and nothing else
from any output. Prompts, model output, reasoning and the contents of patches
and files are skipped.

It never reads `~/.codex/history.jsonl` (prompts), `auth.json`, `config.toml` or
the Codex databases.

### Other files

- `~/.aws/config`: only `sso_account_id`, `role_arn` and `source_profile`. Every
  other line, including any credentials, is dropped as it is read.
- The git config of the folders the agents worked in, for remote URLs. Folders
  in WSL, reached from Windows as `\\wsl.localhost\...`, are outside the
  profile and not read; there the remote Codex recorded for the session is used.

### Finding users as root

As root, the tool finds users in the account database: uid 500 and up on macOS,
1000 and up on Linux, and root. It does not rely on `HOME`, `CLAUDE_CONFIG_DIR`
or `CODEX_HOME`.

On Windows, as an administrator or SYSTEM, it reads the profile folders listed
under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` for
people's accounts (SIDs starting `S-1-5-21-`), and only those that hold logs.
Without administrator rights it reads only the current user's profile.

### Machine identity

- **macOS:** the serial number and hardware UUID, from `ioreg`.
- **Linux:** `/etc/machine-id` and, as root, the product serial number.
- **Windows:** the BIOS serial number, from `Get-CimInstance Win32_BIOS`, and
  `MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography`.

The hardware ID is written only as a hash. The OS is written with its version
or build number.

## What it writes

The tool writes one JSON file with mode `0600`. The file is written whole or not
at all, never through a link, and never into a folder that other users can write
to.

Commands are written only as the examples described below: at most 100
characters, with secrets masked. Command output, code, file contents and
credentials are never written.

### Findings

For each rule that matched:

- Its ID, source, severity and count
- How many sessions it matched in
- The closest MITRE ATT&CK tactic
- Up to three examples of at most 100 characters, with secrets masked and home
  folders, macOS, Linux or Windows, shown as `~` for the user's own and `~other`
  for anyone else's

### Systems reached

- AWS accounts, with profile names
- Azure and Google Cloud accounts
- Repositories, clusters, registries and web hosts, with read and change counts.
  For a repository, comments, reviews, reactions, labels and issues are counted
  apart, as conversation, not as changes
- SSH hosts, with the number of commands that reached each one
- MCP servers, with their tool names and the number of calls, reads and changes

An MCP call counts as a read or a change according to its tool, using the first
of these that applies:

1. The tool's entry in the list of well-known servers
   (`source/rules/mcp_tools.json`)
2. The SQL that a SQL tool runs, of which only whether it writes is kept
3. The verb in the tool's name

A call that matches none of these is counted only as a call. Tool arguments are
not written.

### Other code

- How many commands ran scripts, inline code, builds or containers
- Of the other commands, how many changed a repository or registry, a cloud
  account or cluster, or a web host, each counted once by the first kind

### Users

For each user, numbered `user-1`, `user-2` and so on, never by name:

- How many sessions they had, per agent when there are Codex sessions
- How many sessions fell in each group, by worst risky action and by kind of
  asset changed

### Sessions

The file holds a record for each session that ran or attempted a medium- or
high-risk action, or that changed an asset, up to 5,000 sessions. Each record
contains:

- An ID made by hashing the agent's session ID with a random value generated for
  this run, so it can't be matched to the logs or to another run
- The agent: `"agent": "codex"` for a Codex session; a Claude Code session's
  record has no `agent` field
- When the session started and ended
- The Claude Code or Codex version
- The repository it mostly worked in, as `owner/repo` from its git remote (for
  Codex, otherwise the remote Codex recorded for the session), or
  `local project`
- Its counts of commands, MCP calls, web fetches and tool uses
- Each rule it matched, with the time, up to 200 rules and with at most three
  examples per rule, as described under [Findings](#findings)
- The assets it changed, with counts
- How many of its commands ran other code

A session record does not include who ran the session, a folder path, prompts or
output.

### Machine and tool details

- Claude Code and Codex versions
- How many log entries couldn't be read
- How many times each tool was used
- The machine's name (its serial number unless you set `--name`), a hash of its
  host name, a hashed hardware ID and the OS. The host name itself is never
  written, because it often holds the owner's name.
- The first and last day of activity

## What it sends

**Nothing, unless an upload link is set.** With a link, it sends only the
collected file, in one HTTPS `PUT`, to the host the link names. See
[Uploading to your own storage](upload.md).

## Limits

- **Platforms:** macOS, Linux and Windows 11. On Windows, Claude Code's
  PowerShell tool, Git Bash commands and Codex's PowerShell and cmd commands
  are read, as are commands run in WSL through `wsl`. Logs kept inside a WSL
  distribution are not read from Windows; run the collector inside WSL for
  those.
- **Agents:** Claude Code and the Codex CLI only, along with other Codex clients
  that write the same session logs.
- **Log locations:** logs are read from `~/.claude` and `~/.codex`. If they are
  kept elsewhere through `CLAUDE_CONFIG_DIR` or `CODEX_HOME`, the machine shows
  no activity.
- **Codex counting:** an action that its log records more than one way, such as
  a tool call and its result event or a forked session's copied history, is
  counted once, and so is the same rollout kept in both `sessions` and
  `archived_sessions`. A subagent's commands count in its parent's session.
  Commands a user types in Codex with `!` are not counted.
- **Codex code mode:** the commands a code mode script runs are read from the
  script when the log has no record of each. A script whose commands are built
  as it runs is counted as a log entry with commands that couldn't be read.
- **Size limits:** session logs over 256 MB and log entries over 1 MB are
  skipped and counted. An oversized entry is almost always a pasted image or
  long command output. One that holds the agent's commands is counted
  separately, and the report warns about it.
- **Visibility:** the tool sees only what the logs record. It counts what a
  script, build or remote host did, but doesn't analyse it. Findings come from
  patterns in command text, not from an AI model.
