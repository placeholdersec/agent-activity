#!/usr/bin/env python3
"""Agent activity collector.

Reads the Claude Code and Codex session logs on this endpoint and writes one JSON file:
the risky actions the agents' commands took, the resources they read or
changed, and how many commands ran code whose actions the logs don't show.
Read-only, standard library only; the one network call is the optional
upload of that file. `report [FOLDER]` builds the organisation report from the
collected files (report.py). See README.md.
"""

import argparse
import collections
import configparser
import contextlib
import datetime
import difflib
import functools
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import re
import shlex
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.2"
SCHEMA = "agent-activity-endpoint/1"
HERE = pathlib.Path(__file__).resolve().parent
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
KINDS = ("aws", "azure", "gcp", "repositories", "kubernetes", "registries", "web", "mcp", "ssh")
# Limits, so that no file a user writes can make the run slow or large.
FILE_MAX = 256 * 2**20
LINE_MAX = 2**20
SMALL_MAX = 64 * 2**10
TEXT_MAX = 16 * 2**10
COMMAND_MAX = 256 * 2**10
ERRORS = collections.Counter(homes_skipped=0, files_skipped=0, calls_skipped=0, large_entries_skipped=0)
# Sessions kept with their own record: those with a medium- or high-risk action
# or a change. Their ids are hashed with a salt made fresh for each run, so the
# agent's session id never leaves the machine and runs can't be joined.
SESSION_SALT = os.urandom(16)
SESSIONS_MAX = 5000
SESSION_FINDINGS_MAX = 200
SESSION_EXAMPLES_MAX = 3
# An agent's turn, which may hold tool calls; the entry's type and role come
# before its content.
AGENT_TURN = re.compile(r'"(type|role)"\s*:\s*"assistant"|"type"\s*:\s*"tool_use"')
# A Codex rollout entry that may hold a command, a patch or an MCP call.
CODEX_CALL = re.compile(r'"type"\s*:\s*"(function_call|local_shell_call|custom_tool_call|exec_command_end'
                        r'|mcp_tool_call_end|CommandExecution|McpToolCall)"')


def skip_entry(line, calls=AGENT_TURN):
    """Count an oversized log entry, separately when it holds tool calls."""
    ERRORS["calls_skipped" if calls.search(line[:SMALL_MAX]) else "large_entries_skipped"] += 1


def shipped(name):
    """A file that ships with the tool: embedded in agent-activity.py, else next to this file."""
    bundle = sys.modules.get("agent_activity_files")
    return bundle.FILES[name] if bundle else (HERE / name).read_bytes()


def rule_files():
    bundle = sys.modules.get("agent_activity_files")
    names = [n[len("rules/"):] for n in bundle.FILES if n.startswith("rules/")] if bundle \
        else os.listdir(HERE / "rules")
    return sorted(n for n in names if n.endswith(".json") and "/" not in n)


AWS, GITHUB, SECRETS, SHELL, KNOWN, MCP, SIGMA, READ_ONLY = (json.loads(shipped("rules/" + n)) for n in (
    "aws.json", "github.json", "secrets.json", "shell.json", "known_sources.json", "mcp_tools.json",
    "sigma.json", "read_only.json"))
GITHUB = [dict(r, pattern=re.compile(r["pattern"])) for r in GITHUB]
# Sigma's process rules indexed by the program they need, so a part is matched
# against few; `keys` are words any match holds, and the screen finds those of
# the rules that need no program.
SIGMA_BY_IMAGE, SIGMA_ANY = {}, []
# Sigma rules that fire on what coding agents do every day: a browser's User-Agent to get past
# bot checks (dropped), and the developer's own clipboard and disk images (low).
SIGMA_DROPPED = {"proc_creation_lnx_susp_curl_useragent"}
SIGMA_LOW = {"proc_creation_macos_pbpaste_execution", "proc_creation_macos_hdiutil_mount"}
for _rule in sorted(SIGMA["process"], key=lambda r: r["severity"] != "high"):
    if _rule["id"] in SIGMA_DROPPED:
        continue
    _rule = dict(_rule, pattern=re.compile(_rule["pattern"], re.S),
                 severity="low" if _rule["id"] in SIGMA_LOW else _rule["severity"])
    for _name in _rule["images"] or []:
        SIGMA_BY_IMAGE.setdefault(_name, []).append(_rule)
    if not _rule["images"]:
        SIGMA_ANY.append(_rule)
SIGMA_SCREEN = re.compile(SIGMA["screen"])
# EXPLAIN without ANALYZE runs nothing.
EXPLAIN = r"(?i)\bexplain\s+(?!analy[sz]e\b|\([^)]*analy[sz]e)"
SHELL = [dict(r, pattern=re.compile(r["pattern"]),
              unless=[re.compile(u) for u in r["unless"] + [EXPLAIN] * r["id"].startswith("database:")])
         for r in SHELL]

# Rules for what the sources don't cover. Git's options before its command
# are bounded (`{0,8}`) so matching stays linear.
GIT = r"^git\s+(?:\S+\s+){0,8}"
# Program -> (its publish command, the option naming another registry, the default registry).
PUBLISHERS = {**dict.fromkeys(("npm", "pnpm", "yarn"), ("publish", "--registry", "registry.npmjs.org")),
              "twine": ("upload", "--repository-url", "upload.pypi.org"),
              "poetry": ("publish", None, "upload.pypi.org"),
              "cargo": ("publish", None, "crates.io"), "gem": ("push", None, "rubygems.org")}
# The environment, or a variable named for a secret, shown whole. Filtered
# by grep it is mostly names that hold none.
ENV_PRINTED = {"source": "own", "id": "environment-printed", "tactic": "Credential Access",
               "severity": "medium"}
OWN = [
    # Changes what everyone installing it runs.
    {"source": "own", "id": "package-published", "tactic": "Impact", "severity": "high",
     "pattern": re.compile("|".join(rf"^{p}\s+{verb}\b" for p, (verb, _, _) in PUBLISHERS.items()))},
    {"source": "own", "id": "github-token-printed", "tactic": "Credential Access", "severity": "medium",
     "pattern": re.compile(r"\bgh\s+auth\s+(token\b|status\b.*\s(-t|--show-token)\b)")},
    {"source": "own", "id": "cloud-token-printed", "tactic": "Credential Access", "severity": "medium",
     "pattern": re.compile(r"^gcloud\s+(auth\s+(application-default\s+)?print-(access|identity)-token\b"
                           r"|config\s+config-helper\b)|^az\s+account\s+get-access-token\b"
                           r"|^aws\s+(configure\s+export-credentials|sts\s+get-session-token)\b")},
    # The disk under the file system, overwritten or formatted.
    {"source": "own", "id": "disk-overwritten", "tactic": "Impact", "severity": "high", "local": True,
     "pattern": re.compile(r"^dd\b.*\sof=/dev/(r?disk\d|sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk\d)"
                           r"|^(mkfs(\.\w+)?|mke2fs|mkswap|wipefs|newfs\w*)\s(.*\s)?/dev/\S"
                           r"|^diskutil\s+(erase\w*|zeroDisk|randomDisk|secureErase|partitionDisk|reformat)\b")},
    {"source": "own", "id": "infrastructure-destroyed", "tactic": "Impact", "severity": "high",
     # `terraform destroy -auto-approve` is shellfirm's rule.
     "pattern": re.compile(r"^terraform\s+destroy\b(?!.*\s-auto-approve\b)|^tofu\s+destroy\b"
                           r"|^(terraform|tofu)\s+apply\b.*\s-destroy\b|^(pulumi|cdk)\s+destroy\b")},
    {"source": "own", "id": "database-migrated", "tactic": "Impact", "severity": "medium",
     "pattern": re.compile(r"^supabase\s+db\s+(push|execute)\b(?!.*\s[\"']?(?i:select|show|explain)\s)")},
    {"source": "own", "id": "database-reset", "tactic": "Impact", "severity": "high",
     "pattern": re.compile(r"^supabase\s+db\s+reset\b.*--linked|^supabase\s+db\s+reset\b.*--db-url")},
    {"source": "own", "id": "function-deployed", "tactic": "Execution", "severity": "medium",
     "pattern": re.compile(r"^supabase\s+functions\s+deploy\b")},
    {"source": "own", "id": "platform-secret-set", "tactic": "Persistence", "severity": "medium",
     "pattern": re.compile(r"^supabase\s+secrets\s+set\b")},
    # -w prints the password, dump-keychain -d the secrets (often an agent's own
    # OAuth token); not when discarded.
    {"source": "own", "id": "keychain-read", "tactic": "Credential Access", "severity": "high",
     "pattern": re.compile(r"^security\s+(find-(generic|internet)-password\b(?!.*\s[1&]?>\s*/dev/null)"
                           r".*\s-w\b|dump-keychain\b.*\s-d\b)|^secret-tool\s+(lookup|search)\b")},
    # A secret's value; `--query` naming other fields reads metadata.
    {"source": "own", "id": "secret-value-read", "tactic": "Credential Access", "severity": "high",
     "pattern": re.compile(r"^(kubectl|oc)\s+(\S+\s+){0,8}get\s+secrets?\b.*\s(-o|--output)[ =]?"
                           r"(yaml|json|jsonpath|go-template)"
                           r"|^vault\s+(read|kv\s+get)\s|^gcloud\s+secrets\s+versions\s+access\s"
                           r"|^az\s+keyvault\s+secret\s+(show|download)\s"
                           r"(?!.*--query(?![ =][\"']?value\b[\"']?(\s|$)))"
                           # `doppler secrets` alone lists the values too.
                           r"|^doppler\s+secrets(?!.*\s--only-names\b)(\s*$|\s+(get|download)\b|\s+-)"
                           r"|^doppler\s+run\b.*\s--\s+(printenv\b|env\s*$)"
                           r"|^op\s+(?!.*(?i:public.key|username))(read|item\s+get\b.*\s--reveal\b)")},
    {"source": "own", "id": "cloud-metadata-credentials", "tactic": "Credential Access", "severity": "high",
     "pattern": re.compile(r"^(curl|wget)\b.*(169\.254\.169\.254|metadata\.google\.internal"
                           r"|\[?fd00:ec2::254\]?)\S*(security-credentials|/api/token|/token\b|identity"
                           r"|service-accounts)")},
    # `local`: actions an egress control can't see; `local_only`: they affect
    # only the developer's own, disposable state, so they set no risk group.
    # Undoing edits to named files (`checkout -- <paths>`, `restore`) and
    # `clean -n` are not counted.
    {"source": "own", "id": "local-history-discarded", "tactic": "Impact", "severity": "medium",
     "local": True, "local_only": True,
     "pattern": re.compile(GIT + r"(reset\s+(.*\s)?--hard\b"
                           r"|clean\b(?!.*\s(-\w*n|--dry-run)\b)\s+(.*\s)?(-\w*f|--force)"
                           r"|stash\s+(drop|clear)\b)")},
    # Mostly tidying up after a merge, but an unmerged branch goes with it.
    {"source": "own", "id": "local-branch-deleted", "tactic": "Impact", "severity": "low",
     "local": True, "local_only": True,
     "pattern": re.compile(GIT + r"branch\s+(.*\s)?-D\b")},
    {"source": "own", "id": "hooks-bypassed", "tactic": "Defense Evasion", "severity": "low", "local": True,
     "pattern": re.compile(GIT + r"(commit|push|merge|rebase)\b.*\s--no-verify\b")},
    {"source": "own", "id": "scheduled-job", "tactic": "Persistence", "severity": "medium", "local": True,
     "pattern": re.compile(r"^systemctl\s+(--user\s+)?enable\b|^launchctl\s+(load|bootstrap)\b"
                           r"|^crontab\b(?!.*\s-l\b)\s+\S|^cloudflared\s+(.*\s)?service\s+install\b")},
    # A key that signs in to this account, here or on a host reached by ssh.
    {"source": "own", "id": "ssh-key-authorized", "tactic": "Persistence", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^ssh-copy-id\b|(^|\s)(>>?|^tee\s+(-\S+\s+)*)\s*((~|\$\{?HOME\}?|/\S*)/\.ssh/)?"
                           r"authorized_keys2?\b|^(cp|mv|install)\s.*\s(\S*/\.ssh/)?authorized_keys2?$")},
    # Merges past required reviews and checks.
    {"source": "own", "id": "branch-protection-bypassed", "tactic": "Defense Evasion", "severity": "medium",
     "pattern": re.compile(r"^gh\s+pr\s+merge\b.*\s--admin\b")},
    # shellfirm has `gh secret delete`, not its alias.
    {"source": "own", "id": "ci-secret-deleted", "tactic": "Impact", "severity": "high",
     "pattern": re.compile(r"^gh\s+secret\s+remove\b")},
    # A coding agent run with its permission prompts and sandbox off.
    {"source": "own", "id": "agent-guardrails-off", "tactic": "Defense Evasion", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^claude\b.*\s(--dangerously-skip-permissions"
                           r"|--permission-mode[ =]bypassPermissions)(\s|$)"
                           r"|^codex\b.*\s(--dangerously-bypass-approvals-and-sandbox|--yolo"
                           r"|(-s|--sandbox)[ =]danger-full-access)(\s|$)"
                           r"|^gemini\b.*\s(--yolo|-y|--approval-mode[ =]yolo)(\s|$)")},
    # Atomic Red Team techniques no other rule covers.
    {"source": "own", "id": "system-shutdown", "tactic": "Impact", "severity": "high", "local": True,
     "pattern": re.compile(r"^(?:(shutdown|reboot|halt|poweroff)\b(?!.*\s-c\b)|.*>\s*/proc/sysrq-trigger"
                           r"|systemctl\s+(reboot|poweroff|halt|kexec)\b|init\s+[06]$)")},
    # Runs in every new shell of the user, or of all users.
    {"source": "own", "id": "shell-startup-changed", "tactic": "Persistence", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^(?:.*>>?\s*|tee\s+(-\S+\s+)*|sed\s+(\S+\s+)*-i\S*\s+(\S+\s+)*)"
                           r"((~|/\S+)/\.(bash(rc|_profile|_login|_logout)|zshrc|zprofile|zshenv|zlogin"
                           r"|profile|shrc)|/etc/(profile(\.d/\S*)?|bash\.bashrc|zshrc))(\s|$)")},
    # Who may sign in or become root, and what every program loads first.
    {"source": "own", "id": "login-or-sudo-config-changed", "tactic": "Privilege Escalation",
     "severity": "high", "local": True,
     "pattern": re.compile(r"^(?:.*>>?\s*|tee\s+(-\S+\s+)*|sed\s+(\S+\s+)*-i\S*\s+(\S+\s+)*"
                           r"|(cp|mv|install|ln)\s.*\s)/etc/(pam\.d/\S*|sudoers(\.d/\S*)?|ld\.so\.preload)"
                           r"(\s|$)")},
    {"source": "own", "id": "kernel-module-loaded", "tactic": "Persistence", "severity": "high",
     "local": True,
     "pattern": re.compile(r"^(insmod|kextload)\s|^kmutil\s+load\b"
                           r"|^modprobe\b(?!.*\s(-r|--remove|-n|--dry-run|-c|--showconfig)\b)\s+(-\S+\s+)*"
                           r"[\w-]+")},
    {"source": "own", "id": "setuid-set", "tactic": "Privilege Escalation", "severity": "high", "local": True,
     "pattern": re.compile(r"^chmod\s+(-\S+\s+)*([ugoa]*\+[rwxXt]*s|[0-7]?[2-7][0-7]{3}\s)|^setcap\s")},
    {"source": "own", "id": "root-certificate-trusted", "tactic": "Defense Evasion", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^(update-ca-certificates|update-ca-trust|certctl\s+rehash)\b|^trust\s+anchor\s"
                           r"|^security\s+add-trusted-cert\s|^mkcert\s+(-\S+\s+)*-install\b"
                           r"|^(cp|mv|install|ln)\s.*\s(/usr/local/share/ca-certificates"
                           r"|/etc/pki/ca-trust/source/anchors|/usr/local/share/certs)/?\S*$")},
    # macOS asks before opening a download; this skips the question.
    {"source": "own", "id": "gatekeeper-bypassed", "tactic": "Defense Evasion", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^xattr\s+(-\S+\s+)*-\w*[dc]\w*\s+(\S+\s+)*com\.apple\.quarantine\b"
                           r"|^xattr\s+(-\S+\s+)*-\w*c"
                           r"|^spctl\s+(.*\s)?--(master-disable|global-disable|add)\b")},
    # A port on this machine reachable from the internet.
    {"source": "own", "id": "tunnel-opened", "tactic": "Command and Control", "severity": "medium",
     "pattern": re.compile(r"^ngrok\s+(http|tcp|tls|start)\b|^devtunnel\s+host\b"
                           r"|^frpc\b(?!\s+(-v|--version|-h|--help|verify)\b)"
                           r"|^cloudflared\s+(.*\s)?tunnel\s+(.*\s)?(--url\b|run\b)"
                           r"|^code\s+tunnel\b(?!\s+(status|user|kill|prune|unregister))"
                           r"|^(lt|localtunnel)\s+(.*\s)?--port\b"
                           r"|^tailscale\s+funnel\b(?!.*\s(off|status|reset)\b)")},
    {"source": "own", "id": "packet-capture", "tactic": "Credential Access", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^(tcpdump|tshark|dumpcap|termshark)\b"
                           r"(?!.*\s(-[a-zA-Z]*r[a-zA-Z]*|-D|--list-interfaces|--version|-h)\b)")},
    {"source": "own", "id": "browser-credentials-read", "tactic": "Credential Access", "severity": "high",
     "local": True,
     "pattern": re.compile(r"^(?!(test|\[|ls|stat)\s).*(Login Data|Cookies\.binarycookies|/cookies\.sqlite"
                           r"|/logins\.json|/key4\.db|/(Default|Profile \d+)(/Network)?/Cookies\b"
                           r"|\s--cookies-from-browser\b)")},
    # Runs in every Python process started from that environment.
    {"source": "own", "id": "python-startup-hook", "tactic": "Persistence", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^(?:.*>>?\s*|tee\s+(-\S+\s+)*)\S*(\.pth|/(user|site)customize\.py)(\s|$)")},
    {"source": "own", "id": "remote-desktop-enabled", "tactic": "Lateral Movement", "severity": "medium",
     "local": True,
     "pattern": re.compile(r"^systemsetup\s+(.*\s)?-setremotelogin\s+on\b")},
]

# Matched on a whole segment, pipes included.
OWN_SEGMENT = [
    # One file piped to ssh (cat f | ssh h 'cat > f') is mostly a deploy, and so is an archive of a
    # project unpacked on the other side.
    {"source": "own", "id": "archive-piped-out", "tactic": "Exfiltration", "severity": "low",
     "pattern": re.compile(r"\b(tar|zip)\b[^;&\n]{0,2000}\|\s*(ssh|nc|ncat|netcat|socat)\s")},
    # A shell whose input and output go to a remote host.
    {"source": "own", "id": "reverse-shell", "tactic": "Execution", "severity": "high",
     "pattern": re.compile(r"\b(ba|z|da|k)?sh\s+(-\w+\s+)*-i\b[^;\n]{0,200}/dev/(tcp|udp)/"
                           r"|/dev/(tcp|udp)/\S+[^;\n]{0,50}\s0[<>]&[12]\b|\bexec\s+\d+<>\s*/dev/(tcp|udp)/"
                           r"|\bsocat\b[^;|&\n]{0,300}\b(exec|system):[^\s]{0,40}\b(ba|z|da|k)?sh\b"
                           r"|\b(nc|ncat|netcat)\s[^;|&\n]{0,200}\|\s*(/bin/|/usr/bin/)?(ba|z|da|k)?sh\b")},
    {"source": "own", "id": "dns-exfiltration", "tactic": "Exfiltration", "severity": "medium",
     "pattern": re.compile(r"(^|\|\s*)(dig|nslookup|host)\s+[^;&|\n]{0,2000}\$\(")},
    dict(ENV_PRINTED, pattern=re.compile(r"(^|\|\s*)(sudo\s+)?(env|printenv(\s+\w*(?i:pass|pwd|token|secret"
                                         r"|key|auth|cred)\w*)?)(\s*\|\s*(sort|head|tail|less|more|cat)\b"
                                         r"(?!\s+(-\S+\s+)*-\w*c\b)[^|;&\n]*?)*(\s+2>\S+)*\s*$")),
    # The password in the command, and so in the logs.
    {"source": "own", "id": "sudo-password-in-command", "tactic": "Credential Access", "severity": "medium",
     "pattern": re.compile(r"\b(echo|printf)\b[^|;&\n]{0,500}\|\s*sudo\s+(-\w+\s+(['\"][^'\"]*['\"]\s+)?)*"
                           r"-\w*S\b|\bsudo\s+(-\w+\s+(['\"][^'\"]*['\"]\s+)?)*-\w*S\b[^|;&\n]*<<<")},
]

WIPED = {"high": {"source": "own", "id": "home-or-root-deleted", "tactic": "Impact", "severity": "high",
                  "local": True},
         "system": {"source": "own", "id": "system-folder-deleted", "tactic": "Impact", "severity": "high",
                    "local": True},
         "medium": {"source": "own", "id": "project-deleted", "tactic": "Impact", "severity": "medium",
                    "local": True, "local_only": True}}

PUBLIC_REPO = {"source": "own", "id": "public-repo-created", "action": "public-repo-created",
               "tactic": "Exfiltration", "severity": "low"}

# Uploading a local file is exfiltration; to a known drop site, more so.
DROP_SITES = re.compile(r"(^|\.)(transfer\.sh|file\.io|0x0\.st|webhook\.site|pastebin\.com|hastebin\.com|"
                        r"termbin\.com|hooks\.slack\.com|discord(app)?\.com|ngrok\.io|ngrok-free\.app)$")

# Code fetched and run, and packages installed from a URL, rank by where the
# code comes from: rules/known_sources.json.
TIER_IDS = {"pinned": "known-pinned", "unpinned": "known-unpinned", "unknown": "unknown"}
FETCHED = {family: {tier: {"source": "own", "id": f"{family}:{TIER_IDS[tier]}", "tactic": "Execution",
                           "severity": KNOWN["tiers"][tier]} for tier in TIER_IDS}
           for family in ("download-run", "package-from-url")}
INSTALLERS = [dict(r, pinned=re.compile(r["pinned"]) if r.get("pinned") else None)
              for r in KNOWN["installers"]]
FETCHERS = {"curl", "wget", "iwr", "irm", "Invoke-WebRequest", "Invoke-RestMethod"}
FETCH_NAMED = re.compile(r"\b(%s)\b" % "|".join(sorted(FETCHERS)))
# Run with a fetch's output as its code, given no script of its own.
PIPED_INTO = re.compile(r"^((ba|z|da|k|fi)?sh|source|python[\d.]*|perl|ruby|node|iex|Invoke-Expression)$",
                        re.I)
# `bash <(curl …)`, `sh -c "$(curl …)"`, `eval "$(curl …)"`; `sh "$(curl …)"`
# runs a file the output names, not the output.
SUBSTITUTED = re.compile(r"(?<![\w./-])(?:[\w.-]*/)*"
                         r"(?:(?:(?:ba|z|da|k)?sh|source|\.|python[\d.]*|perl|ruby|node)\s+(?:-\w+\s+)*<\("
                         r"|(?:eval|(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*-\w*c|python[\d.]*\s+(?:-\w+\s+)*-c"
                         r"|(?:perl|ruby|node)\s+(?:-\w+\s+)*-\w*e)\s+[\"']?(?:\$\(|`))"
                         r"\s*(?P<fetch>(?:curl|wget)\s[^)`]*)")
PACKAGE_URL = re.compile(
    # A package index or mirror (`--index-url https://…`) is not a package.
    r"^(pip3?|pipx|uv\s+pip|uv\s+tool|uv)\s+(install|add)\b.*(?<!-url)(?<!\s-i)(?<!-links)(?<!\s-f)"
    r"\s(git\+\S+|https?://\S+)"
    r"|^(npm|pnpm|yarn|bun)\s+(install|add|i)\b.*\s(github:\S+|git\+\S+|https?://\S+)"
    r"|^(uvx|pipx\s+run|uv\s+tool\s+run)\b.*\s(--from[ =]|--spec[ =])?(git\+\S+|https?://\S+)"
    r"|^(npx|bunx|pnpm\s+dlx)\s+(-\S+\s+)*(github:\S+|git\+\S+)")
CODE_HOSTS = {"github.com": "github.com", "raw.githubusercontent.com": "github.com",
              "codeload.github.com": "github.com", "gitlab.com": "gitlab.com",
              "bitbucket.org": "bitbucket.org"}
VERSION_REF = re.compile(r"^(v?\d+(\.\d+)+[\w.+-]*|(?=[0-9a-f]*\d)[0-9a-f]{7,40})$")

# --- Reading a command ---

QUOTED = r"""("([^"\\]|\\.)*"|'[^']*')"""
QUOTED_FLAGS = re.compile(r"\s(-m|--message|--body|--title|--notes|-b|-t)\s+" + QUOTED)
PRINTED = re.compile(r"\b(echo|printf)((?:\s+-\w+)*)((?:\s+" + QUOTED + r")+)")
HEREDOC = re.compile(r"""<<-?[ \t]*['"]?(\w+)['"]?([^\n]{0,200})\n""")
QUOTING = re.compile(r"['\"\\#]")
UNQUOTED_WORD = re.compile(r"[^ \t\r\n]+")
# A word's plain text, quoted text, escaped character, the space between words, or `#`.
SHELL_PIECE = re.compile(r"""([^ \t\r\n'"\\#]+)|'([^']*)'|"([^"\\]*(?:\\[\s\S][^"\\]*)*)"|\\([\s\S])"""
                         r"|([ \t\r\n]+)|(#)")
DOUBLE_ESCAPE = re.compile(r'\\([\\"])')
# Programs that run the command after them, with their options that take a
# value. `command -v` looks a program up, so its options are not skipped.
WRAPPERS = {"sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "--user", "--group"},
            "env": {"-u", "--unset", "-C", "--chdir"}, "time": set(), "nohup": set(), "command": None,
            "exec": {"-a"}, "nice": {"-n"}, "timeout": {"-s", "--signal", "-k", "--kill-after"},
            "caffeinate": {"-t", "-w"}, "doas": {"-u", "-C"},
            "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs",
                      "--delimiter", "--arg-file", "--replace"}}
SHELLS = {"bash", "sh", "zsh"}
SHELL_SCRIPT_FLAG = re.compile(r"^-[a-zA-Z]*c$")
KEYWORDS = {"if", "then", "else", "elif", "while", "until", "do", "!", "{"}
RUNNERS = {"uv": {"--with", "-w", "--python", "-p", "--project", "--directory", "--package", "--extra",
                  "--group", "--env-file", "--index", "--with-requirements", "--with-editable"},
           "poetry": set(), "pipenv": set()}
FUNCTION = re.compile(r"(?:^|(?<=[\s;&|(){]))(?:function\s+)?([A-Za-z_][\w-]{0,63})\s*\(\)\s*\{(.{0,4000}?)"
                      r"[;\n]\s*\}", re.S)
# A function body that runs its arguments.
RUNS_ARGS = re.compile(r"(^|\s)(eval|exec|(ba|z)?sh\s+-c)\s|(^|[;&|{(\n])\s*\"?\$[@*1-9]")


def shell_split(text, comments=False):
    """Same result as shlex.split(text, comments)."""
    if not QUOTING.search(text):
        return UNQUOTED_WORD.findall(text)
    out, word, at = [], None, 0
    while at < len(text):
        piece = SHELL_PIECE.match(text, at)
        if not piece:
            raise ValueError("No closing quotation")
        at, kind = piece.end(), piece.lastindex
        if kind == 5 or (kind == 6 and comments):
            if word is not None:
                out.append("".join(word))
                word = None
            if kind == 6:
                at = text.find("\n", at) + 1 or len(text)
            continue
        word = word or []
        word.append(DOUBLE_ESCAPE.sub(r"\1", piece.group(3)) if kind == 3 else piece.group(kind))
    if word is not None:
        out.append("".join(word))
    return out


def printed(match):
    """Blanks echo/printf text, keeping double-quoted text with a substitution."""
    kept = [q.group(0) for q in re.finditer(QUOTED, match.group(3))
            if q.group(0).startswith('"') and ("$(" in q.group(0) or "`" in q.group(0))]
    return match.group(1) + match.group(2) + " " + (" ".join(kept) or "''")


WORD_RUN = re.compile(r"[^'\"\\$`()&|;\n \t]+")


def simple_commands(command):
    """Each simple command as a list of (start, end, substituted) word spans.
    `$(…)` and backticks hold simple commands of their own; `substituted` marks
    a word that contains one outside single quotes."""
    done, levels, i = [], [{"words": [], "word": None, "quote": None, "close": None}], 0

    def end_word(level, at):
        if level["word"]:
            level["words"].append((level["word"][0], at, level["word"][1]))
            level["word"] = None

    def end_command(level, at):
        end_word(level, at)
        if level["words"]:
            done.append(level["words"])
            level["words"] = []

    while i < len(command):
        level, c = levels[-1], command[i]
        if level["quote"] == "'":
            level["quote"], i = None, command.find("'", i) + 1 or len(command)
            continue
        plain = WORD_RUN.match(command, i)
        if plain:
            level["word"] = level["word"] or [i, False]
            i = plain.end()
            continue
        if level["quote"] is None and level["close"] == c:
            end_command(level, i)
            levels.pop()
            i += 1
            continue
        if not level["word"] and c not in " \t\n;&|()":
            level["word"] = [i, False]
        if c == "\\":
            i += 2
            continue
        # Deeper nesting is read as plain text, since the work grows with
        # the square of the depth.
        if (command.startswith("$(", i) or c == "`") and len(levels) < 8:
            level["word"][1] = True
            levels.append({"words": [], "word": None, "quote": None, "close": ")" if c == "$" else "`"})
            i += 2 if c == "$" else 1
            continue
        if level["quote"] == '"':
            level["quote"] = None if c == '"' else '"'
        elif c in "'\"":
            level["quote"] = c
        elif c in " \t":
            end_word(level, i)
        elif c in "\n;&|()":
            end_command(level, i)
        i += 1
    for level in reversed(levels):
        end_command(level, len(command))
    return done


INTERPRETER_NAME = re.compile(r"^(python[\d.]*|ruby|perl|osascript|node|bun|deno)$")
# Programs whose expression is data: (options that give it, other options
# that take a value).
GREP_VALUED = {"-A", "-B", "-C", "-m", "--max-count"}
EXPRESSION = {"sed": ({"-e", "--expression"}, {"-l"}),
              "awk": (set(), {"-v", "-F"}),
              "grep": ({"-e", "--regexp"}, GREP_VALUED),
              "rg": ({"-e", "--regexp"}, GREP_VALUED | {"-g", "--glob", "-t", "--type", "-T", "--type-not",
                                                        "-r", "--replace", "-M", "--max-columns", "-j",
                                                        "--threads"}),
              "jq": (set(), {"--indent"})}
TWO_VALUED = {"--arg", "--argjson", "--slurpfile", "--rawfile"}
FROM_FILE = {"-f", "--file", "--from-file"}
EXPRESSION.update({name: EXPRESSION[same] for name, same in (
    ("gawk", "awk"), ("mawk", "awk"), ("nawk", "awk"), ("egrep", "grep"), ("fgrep", "grep"), ("gsed", "sed"),
    ("ag", "rg"))})
REDIRECT = re.compile(r"^\d*(<|>|&>)")
REDIRECT_ALONE = re.compile(r"^\d*(<|>>?|&>>?)$")


def program_at(values):
    """The index of the program, past leading assignments, keywords and wrappers."""
    k = 0
    while k < len(values):
        if ASSIGNMENT.match(values[k]) or values[k] in KEYWORDS:
            k += 1
        elif values[k] in WRAPPERS:
            wrapper, valued, k = values[k], WRAPPERS[values[k]], k + 1
            while valued is not None and k < len(values) and values[k].startswith("-"):
                k += 2 if values[k] in valued else 1
            # timeout's duration argument.
            k += wrapper == "timeout"
        else:
            return k
    return None


def inner_at(values, k):
    """The index of the command the program at `k` hands over to (`uv run x`,
    `… -- bash -c`, `docker exec c sh`), or None."""
    program = os.path.basename(values[k])
    if program in RUNNERS and values[k + 1:k + 2] == ["run"]:
        j = k + 2
        while j < len(values) and values[j].startswith("-"):
            if values[j] == "--":
                j += 1
                break
            j += 2 if values[j] in RUNNERS[program] else 1
        return j if j < len(values) else None
    if program != "git" and "--" in values[k + 1:]:
        j = values.index("--", k + 1) + 1
        if j < len(values) and os.path.basename(values[j]) in SHELLS:
            return j
    if program in ("docker", "podman", "kubectl", "oc") and values[k + 1:k + 2] in (["exec"], ["run"]):
        return next((j for j in range(k + 2, len(values)) if os.path.basename(values[j]) in SHELLS), None)
    return None


def remote_at(values, k):
    """The indexes of the command words of the `ssh` at `k`, past its options
    (before and after the host) and without redirects; [] for none."""
    j, host, out = k + 1, False, []
    while j < len(values):
        word = values[j]
        if out or (host and not word.startswith("-")):
            if REDIRECT_ALONE.match(word):
                j += 1
            elif not REDIRECT.match(word):
                out.append(j)
        elif word.startswith("-"):
            j += word in SSH_VALUED
        else:
            host = True
        j += 1
    return out


def run_at(values):
    k = program_at(values)
    while k is not None and (inner := inner_at(values, k)) is not None:
        k = inner
    return k


def data_words(values, functions):
    """The indexes of the words a simple command's program takes as data: a
    `for` list, a script's or a function's arguments, an interpreter's inline
    script, and the expression of sed, awk, grep, rg or jq."""
    k = run_at(values)
    if k is None:
        return []
    program = os.path.basename(values[k])
    if values[k] in ("for", "select") and values[k + 2:k + 3] == ["in"]:
        return list(range(k + 3, len(values)))
    if values[k] in functions or (re.match(r"^\.{0,2}/|^~/", values[k])
                                  and os.path.dirname(values[k]) not in SYSTEM_BIN):
        return list(range(k + 1, len(values)))
    if INTERPRETER_NAME.match(program) or program in SHELLS:
        inline = SHELL_SCRIPT_FLAG if program in SHELLS else r"^(-[a-z]*[ep]|--eval|--print)$" \
            if program in ("node", "bun", "deno") else r"^-[a-zA-Z]*[ce]$"
        j = k + 1
        while j < len(values) and values[j].startswith("-") and values[j] != "-":
            if re.match(inline, values[j]):
                # A shell's `-c` script is commands, which blank_data reads.
                return [] if program in SHELLS else list(range(j + 1, len(values)))
            if values[j] == "-m" and program not in SHELLS:
                return list(range(j + 2, len(values)))
            j += 1
        return list(range(j + 1, len(values))) if j < len(values) and values[j] != "-" else []
    if program not in EXPRESSION:
        return []
    given, valued = EXPRESSION[program]
    out, j = [], k + 1
    while j < len(values):
        word = values[j]
        if word in FROM_FILE or word.startswith(tuple(f + "=" for f in FROM_FILE)):
            return out
        if word in given:
            out.append(j + 1)
            j += 2
        elif word in TWO_VALUED:
            j += 3
        elif word in valued or REDIRECT_ALONE.match(word) or (
                # macOS `sed -i ''`: the empty word is the backup suffix.
                word == "-i" and program in ("sed", "gsed") and values[j + 1:j + 2] == [""]):
            j += 2
        elif REDIRECT.match(word) or (word.startswith("-") and word != "-"):
            j += 1
        else:
            return out or [j]
    return out


def blank_data(command):
    """The command with the words its programs take as data replaced by `'…'`,
    recursing into a shell's `-c` script. Words with a substitution are kept."""
    spans = []
    functions = {m.group(1) for m in FUNCTION.finditer(command) if not RUNS_ARGS.search(m.group(2))} \
        if "()" in command else set()
    for simple in simple_commands(command):
        values = []
        for text in (command[s:e] for s, e, _ in simple):
            try:
                values.append(" ".join(shell_split(text)) if text.strip() else text)
            except ValueError:
                values.append(text)
        for j in data_words(values, functions):
            # Redirect targets stay.
            if j < len(simple) and not simple[j][2] and not REDIRECT.match(values[j]) \
                    and not (j and REDIRECT_ALONE.match(values[j - 1])):
                spans.append((simple[j][0], simple[j][1], "'…'"))
        k = run_at(values)
        program = os.path.basename(values[k]) if k is not None else ""
        at = next((j + 1 for j in range(k + 1, len(values) - 1) if SHELL_SCRIPT_FLAG.match(values[j])),
                  None) if program in SHELLS else None
        if program == "ssh":
            # ssh's command as one word (`ssh h 'cmd'`) is a script.
            remote = remote_at(values, k)
            at = remote[0] if len(remote) == 1 else None
        if at is not None and at < len(simple) and not simple[at][2]:
            script = values[at]
            blanked = blank_data(script)
            if blanked != script:
                spans.append((simple[at][0], simple[at][1], shlex.quote(blanked)))
    out, last = [], 0
    for start, end, text in sorted(spans):
        if start >= last:
            out += [command[last:start], text]
            last = end
    return "".join(out + [command[last:]])


def heredocs(command):
    """The command with each heredoc replaced by `<<heredoc`. A heredoc fed to
    a shell is its script, so its lines are kept as commands. At most 20 are
    replaced, to bound the work."""
    out, last = [], 0
    for _ in range(20):
        start = HEREDOC.search(command, last)
        closing = start and re.compile(r"\n[ \t]*" + re.escape(start.group(1)) + r"\b")
        end = closing and closing.search(command, start.end() - 1)
        if not end:
            break
        line = command[command.rfind("\n", 0, start.start()) + 1:start.start()]
        # The rest of its line stays: `cat <<EOF | bash`, `| curl -d @- …`.
        rest = start.group(2)
        out += [command[last:start.start()], "<<heredoc", rest]
        piped = re.match(r"\s*\|(?!\|)([^|;&]*)", rest)
        if feeds_shell(line) or (piped and feeds_shell(piped.group(1))):
            out.append("\n" + command[start.end():end.start()])
        last = end.end()
    return "".join(out + [command[last:]])


def feeds_shell(line):
    """Whether a heredoc starting at the end of this line is a shell's script
    (`bash <<EOF`, `sudo sh -s`, `ssh host <<EOF`), not data."""
    values = re.split(r"[|;&(]", line)[-1].split()
    k = program_at(values)
    while k is not None and os.path.basename(values[k]) not in SHELLS | {"ssh"}:
        k = inner_at(values, k)
    if k is None:
        return False
    rest = positional(values[k + 1:], SSH_VALUED if values[k] == "ssh" else {"-o", "-O"})
    return len(rest) == (1 if values[k] == "ssh" else 0)


COMMENT_FREE = re.compile(r"[^'\"\\#]+")


def uncommented(command):
    out, quote, i, last = [], None, 0, 0
    while i < len(command):
        c = command[i]
        if quote == "'":
            quote, i = None, command.find("'", i) + 1 or len(command)
            continue
        plain = COMMENT_FREE.match(command, i)
        if plain:
            i = plain.end()
            continue
        if c == "\\":
            i += 1
        elif quote == '"':
            quote = None if c == '"' else quote
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or command[i - 1] in " \t\n;&|()"):
            end = command.find("\n", i)
            out.append(command[last:i])
            last = i = len(command) if end < 0 else end
            continue
        i += 1
    return "".join(out + [command[last:]])


CONTINUED = re.compile(r"'[^']*'?|\\\n|\\.|[^'\\]+", re.S)


def continued(command):
    """The command with its lines joined where they end in a backslash, outside single quotes."""
    if "\\\n" not in command:
        return command
    return "".join("" if piece == "\\\n" else piece for piece in CONTINUED.findall(command))


def runnable(command):
    """The command with text that is printed or passed as data blanked."""
    command = continued(command[:COMMAND_MAX])
    command = PRINTED.sub(printed, blank_data(uncommented(heredocs(command)[:TEXT_MAX])))
    return QUOTED_FLAGS.sub(lambda m: " " + m.group(1) + " ''", command)


PLAIN_RUN = re.compile(r"[^'\"\\$`)&|;\n]+")


SUBSTITUTION = "$(…)"


def split_command(command, segments=False):
    """The pieces of a command between control operators outside quotes.
    Command substitutions are pieces of their own, inside double quotes too,
    and leave `$(…)` in the piece around them, which so stays whole
    (`aws s3 rm "s3://$(…)/x"`). As segments, pipes and substitutions stay in
    their piece (`dig $(…).example.com`)."""
    pieces, current, quote, i, opened, outer = [], [], None, 0, [], []
    ops = ";\n" if segments else ";|\n"
    while i < len(command):
        if quote == "'":
            end = command.find("'", i) + 1 or len(command)
            current.append(command[i:end])
            quote, i = None, end
            continue
        plain = PLAIN_RUN.match(command, i)
        if plain:
            current.append(plain.group())
            i = plain.end()
            continue
        c = command[i]
        if c == "\\" and i + 1 < len(command):
            current.append(command[i:i + 2])
            i += 2
            continue
        if quote is None and c in "'\"":
            quote = c
        elif quote == '"' and c == '"':
            quote = None
        if command.startswith("$(", i) or c == "`" or (c == ")" and quote is None):
            # Quoting restarts inside a substitution and resumes after it.
            closing = c == ")" or (c == "`" and quote is None and opened[-1:] and opened[-1][0] == "`")
            step = 2 if command.startswith("$(", i) else 1
            if segments:
                current.append(command[i:i + step])
            if not closing:
                opened.append((c, quote))
                quote = None
                if not segments:
                    outer.append(current)
                    current = []
            elif opened and opened[-1][0] == ("$" if c == ")" else "`"):
                quote = opened.pop()[1]
                if not segments:
                    pieces.append("".join(current))
                    current = outer.pop() + [SUBSTITUTION]
            elif not segments:
                pieces.append("".join(current))
                current = []
            i += step
            continue
        if quote is None and not (segments and opened) and (command.startswith(("&&", "||"), i) or c in ops):
            pieces.append("".join(current))
            current = []
            i += 2 if command.startswith(("&&", "||"), i) else 1
            continue
        current.append(c)
        i += 1
    pieces += ["".join(p) for p in [current] + outer[::-1]]
    return [p.strip() for p in pieces if p.strip()]


ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def split_part(part):
    try:
        return shell_split(part, comments=True)
    except ValueError:
        return part.split()


def words(part, env, argv=None):
    """The words of one part from its program on, `argv` being its split. An
    `AWS_PROFILE=x` in front of `aws` becomes its `--profile`."""
    argv = split_part(part) if argv is None else argv
    k = program_at(argv)
    profile = next((m.group(2) for m in map(ASSIGNMENT.match, reversed(argv[:k]))
                    if m and m.group(1) == "AWS_PROFILE"), None) or env.get("AWS_PROFILE")
    argv = [] if k is None else argv[k:]
    if argv and os.path.basename(argv[0]) == "aws" and profile and "--profile" not in argv:
        argv = argv + ["--profile", profile]
    return argv


def expand(path, env):
    """A path with a leading `~` as the home in `env`, which is the logs'
    user's, never the collector's own."""
    home = env.get("HOME")
    return home + path[1:] if home and (path == "~" or path.startswith("~/")) else path


def command_parts(command, cwd, env, scripts):
    """((text, argv, folder, path) for each part of a command, the folder it
    ends in), following `cd`. argv starts with the program's base name; path
    is the program as written. A shell's `-c` script goes to `scripts` with
    its folder, ssh's command with None."""
    here = cwd or "/"
    out = []
    for text in split_command(command):
        text = text.strip().lstrip("(").strip()
        # So `f=~/.aws/credentials; cat "$f"` reads as what it does.
        text = VARIABLE.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), text)
        if not text:
            continue
        first = split = split_part(text)
        if first and first[0] == "export":
            first = first[1:]
        if first and all(ASSIGNMENT.match(w) for w in first):
            for w in first:
                name, value = ASSIGNMENT.match(w).groups()
                # One set from a substitution (`d=$(mktemp -d)`) stays a name.
                if value and SUBSTITUTION not in value:
                    env[name] = value
            continue
        argv = words(text, env, split)
        if not argv:
            continue
        if argv[0] == "cd" and len(argv) > 1:
            # PATH_MAX on macOS.
            there = os.path.abspath(os.path.join(here, expand(argv[1], env)[:1024]))
            here = there if len(there) <= 1024 else here
            continue
        add_part(out, argv, here, scripts)
    return out, here


def add_part(out, argv, here, scripts):
    """A part, and the command it runs when it is a runner (`uv run …`)."""
    program = os.path.basename(argv[0])
    flag = next((i for i, a in enumerate(argv[1:-1], 1) if SHELL_SCRIPT_FLAG.match(a)), None)
    if program in SHELLS and flag:
        out.append((program + " -c ''", [program, "-c", ""], here, argv[0]))
        scripts.append((argv[flag + 1], here))
        return
    # `eval` runs its words as a script, `su -c` its command as another user.
    script = " ".join(argv[1:]) if program == "eval" else \
        option(argv, "-c", "--command") if program == "su" else None
    if script:
        out.append((program + " ''", [program, ""], here, argv[0]))
        scripts.append((script, here))
        return
    out.append((" ".join([program] + argv[1:]), [program] + argv[1:], here, argv[0]))
    if program == "ssh":
        # Its command runs on the host, in a folder not known here.
        remote = remote_at(argv, 0)
        if remote:
            scripts.append((" ".join(argv[i] for i in remote), None))
    inner = inner_at(argv, 0)
    if inner is not None:
        add_part(out, argv[inner:], here, scripts)


def option(argv, *names):
    for i, arg in enumerate(argv):
        for name in names:
            if arg == name and i + 1 < len(argv):
                return argv[i + 1]
            if arg.startswith(name + "="):
                return arg.split("=", 1)[1]
    return None


def positional(argv, valued=()):
    out, skip = [], False
    for arg in argv:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg in valued
            continue
        out.append(arg)
    return out


# --- Masking ---

# A variable, option, header or JSON/YAML key name whose value is secret.
SECRET_WORD = re.compile(r"(?i)pass|pwd|auth|cred|key|token|secret|cookie|session")

# Every repetition is bounded or can't overlap itself, so masking is linear.
# The last entry must stay last: `masked(long_runs=False)` drops it.
MASKS = [
    (re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----[^-]*(-----END [A-Z ]{0,30}PRIVATE KEY-----)?"),
     "••••"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "••••"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}"), "••••"),
    (re.compile(r"\bxox[abprs]-[\w-]+|\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}"
                r"|\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{10,}"
                r"|\bAIza[0-9A-Za-z_-]{30,}|\bglpat-[\w-]{20,}|\bnpm_[A-Za-z0-9]{36}"), "••••"),
    (re.compile(r"\b(hooks\.slack\.com/(services|workflows|triggers)/)\S+"), r"\1••••"),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "••••"),
    # Quotes may be gone, so a header value is its scheme and one word, or a
    # cookie's `a=1; b=2`.
    (re.compile(r"(?i)(\b(proxy-)?authorization\s*:\s*"
                r"((basic|bearer|digest|token|negotiate|apikey|aws4-hmac-sha256)\s+)?"
                r"|(-H|--header)[\s=]*[\"']?(?!(proxy-)?authorization)[\w-]{0,40}"
                r"(key|token|secret|auth|session)[\w-]{0,40}\s*:\s*)[^\s\"']{1,4096}"),
     r"\1••••"),
    (re.compile(r"(?i)(\b(set-)?cookie\s*:\s*)[^\s\"';]{1,4096}(;\s*[^\s\"';]{1,4096}){0,50}"), r"\1••••"),
    (re.compile(r"(?i)\bbearer\s+[^\s\"']+"), "Bearer ••••"),
    # A URL's password may hold an `@`: up to the last one before the host.
    (re.compile(r"(://[^/\s:@]{1,128}:)[^\s/?#]{0,256}@"), r"\1••••@"),
    (re.compile(r"((\s-u|--user)[\s=]+[\"']?[^\s:\"']{1,128}:)[^\s\"']+"), r"\1••••"),
    (re.compile(r"(\b(mysql|mysqldump|mariadb)\b[^|;&\n]{0,300}?\s-p)[^\s\"']+"), r"\1••••"),
    (re.compile(r"(\bsshpass\b[^|;&\n]{0,100}?\s-p\s*)\S+"), r"\1••••"),
    # A token given as a URL's user name.
    (re.compile(r"(://)[^/\s:@]{16,256}@"), r"\1••••@"),
    # Passwords given as a client's option.
    (re.compile(r"(\b(?:redis-cli\b[^|;&\n]{0,300}?\s-a|mongo(?:sh)?\b[^|;&\n]{0,300}?\s-p"
                r"|sqlcmd\b[^|;&\n]{0,300}?\s-P|zip\b[^|;&\n]{0,300}?\s-P"
                r"|(?:docker|podman)\s+login\b[^|;&\n]{0,300}?\s-p)\s+)(?!-)(?:\"[^\"\n]*\"|'[^'\n]*'|\S+)"),
     r"\1••••"),
    (re.compile(r"(\b(?:gh\s+secret\s+set\b[^|;&\n]{0,300}?\s(?:--body|-b)|aws\s+ssm\s+put-parameter\b"
                r"[^|;&\n]{0,300}?\s--value)[\s=]+)(?:\"[^\"\n]*\"|'[^'\n]*'|\S+)"), r"\1••••"),
    # Signatures and one-time codes in a URL's query (Azure SAS, presigned URLs, OAuth).
    (re.compile(r"(?i)([?&](?:sig|signature|x-amz-signature|x-goog-signature|code|access_token|refresh_token"
                r"|id_token|client_secret)=)[^&#\s\"']{1,4096}"), r"\1••••"),
    # A password piped or fed to `sudo -S`.
    (re.compile(r"(\b(?:echo|printf)\s+(?:-\w+\s+)?(?:'%s\\n'\s+)?)(?:\"[^\"\n]*\"|'[^'\n]*'|\S+)(?=\s*\|\s*sudo\b[^|;&\n]*\s-S\b)"),
     r"\1••••"),
    (re.compile(r"(\bsudo\b[^|;&\n]*\s-S\b[^|;&\n]*<<<\s*)(?:\"[^\"\n]*\"|'[^'\n]*'|\S+)"), r"\1••••"),
    (re.compile(r"(\baws\s+configure\s+set\s+[\w.-]{0,64}(secret|token|key)[\w.-]{0,64}\s+)\S+"), r"\1••••"),
    (re.compile(r"(?i)(--[\w-]{0,40}(pass|pwd|token|secret|key|auth|cred)[\w-]{0,40}(?<!-stdin)(?<!-file)[ =])(\S+)"), r"\1••••"),
    # A variable, a `-var`, or a JSON/YAML key (`"password": "…"`).
    (re.compile(r"((?<![\w-])([\"']?)(?!(?i:(?:proxy-)?authorization)\W)([A-Za-z_][\w-]{0,63})\2\s*[:=]\s*)"
                r"(?!\$\(|••••|//)(\"[^\"\n]{0,4096}\"|'[^'\n]{0,4096}'|[^\s\"',;}&?#]{1,4096})"),
     lambda m: m.group(1) + "••••" if SECRET_WORD.search(m.group(3)) else m.group(0)),
    (re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}"), lambda m: masked_path(m.group(0))),
]
# A path segment that reads as a name; a token's random text rarely does.
NAME_LIKE = re.compile(r"^[A-Z]?[a-z0-9._-]{0,31}$")


def masked_path(text):
    """A long run with its random-looking path segments hidden."""
    if "/" not in text:
        return "••••"
    return "/".join(p if not p or NAME_LIKE.match(p) else "••••" for p in text.split("/"))


OTHER_HOME = re.compile(r"(?<![\w/.-])/(Users|home)/[^/\s'\"]+")


def masked(text, home, long_runs=True):
    """Text with secrets hidden, the user's home as `~` and other homes as
    `~other`. Without `long_runs`, long runs of letters and digits are kept,
    since a resource name can be one."""
    text = text[:TEXT_MAX]
    if home:
        text = re.sub(re.escape(home.rstrip("/")) + r"(?![^/\s'\"])", "~", text)
    text = OTHER_HOME.sub("~other", text)
    for pattern, replacement in MASKS if long_runs else MASKS[:-1]:
        text = pattern.sub(replacement, text)
    return text


def example(text, home, at=0):
    """The text as a short example, masked whole, then from near `at`, where
    the match is."""
    shown = masked(text, home)
    if at:
        shown = near(shown, len(masked(text[:at], home)))
    shown = " ".join(shown.split())
    return shown if len(shown) <= 100 else shown[:99] + "…"


def distinct(examples, n=3):
    """Up to n of the examples, the first first, then each the least like
    those already picked."""
    pool, picked = list(dict.fromkeys(examples)), list(examples[:1])
    while len(picked) < min(n, len(pool)):
        picked.append(max((x for x in pool if x not in picked),
                          key=lambda x: -max(difflib.SequenceMatcher(None, x, p).ratio() for p in picked)))
    return picked


def plain_name(text, more=""):
    return re.sub(r"[^\w.:/@+•~*%s-]" % more, "_", str(text)[:TEXT_MAX])[:128]


def safe_name(text, home):
    return plain_name(masked(str(text), home, long_runs=False))


# --- Reading a user's files ---
# Each user controls their own files, so a file is read only if it is a
# regular file, not a link, owned by that user and not too big, and a folder
# only if it is in their home. Root reads them as that user as well.

# The user being read: home as given, home with links followed, uid.
OWNER = {"given": "", "home": "/", "uid": -1}


def inside(path):
    """Whether a path, links followed, is in the home being read."""
    try:
        home, real = OWNER["home"], os.path.realpath(path)
    except (OSError, ValueError):
        return False
    return real == home or real.startswith(home.rstrip("/") + "/")


def open_owned(path, limit):
    """(text file, stat) for a file of the user's, or None. A file there but
    not theirs, or too big, is counted."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (FileNotFoundError, NotADirectoryError, ValueError):
        return None
    except OSError:
        ERRORS["files_skipped"] += 1
        return None
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER["uid"] or info.st_size > limit:
        os.close(fd)
        ERRORS["files_skipped"] += 1
        return None
    return os.fdopen(fd, encoding="utf-8", errors="replace"), info


def read_small(path):
    opened = open_owned(path, SMALL_MAX)
    if not opened:
        return None
    with opened[0] as handle:
        return handle.read(SMALL_MAX)


def lines_of(handle, calls=AGENT_TURN):
    """The lines of a session log up to FILE_MAX; longer lines than LINE_MAX
    are skipped and counted."""
    total = 0
    while total < FILE_MAX:
        line = handle.readline(LINE_MAX + 1)
        if not line:
            return
        total += len(line)
        if len(line) > LINE_MAX:
            skip_entry(line, calls)
            while line and not line.endswith("\n"):
                line = handle.readline(LINE_MAX)
                total += len(line)
            continue
        yield line


@contextlib.contextmanager
def as_user(uid, gid):
    """Run as this user while reading their files, when running as root."""
    if os.geteuid() != 0 or uid == 0:
        yield
        return
    groups, egid = os.getgroups(), os.getegid()
    os.setgroups([gid])
    os.setegid(gid)
    os.seteuid(uid)
    try:
        yield
    finally:
        os.seteuid(0)
        os.setegid(egid)
        # macOS can report more groups than setgroups() takes.
        with contextlib.suppress(OSError, ValueError):
            os.setgroups(groups[:os.sysconf("SC_NGROUPS_MAX")])


# --- AWS ---

AWS_GLOBAL_VALUED = {"--profile", "--region", "--output", "--endpoint-url", "--color", "--ca-bundle",
                     "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format", "--query"}
S3_VALUED = {"--exclude", "--include", "--acl", "--storage-class", "--content-type", "--cache-control",
             "--sse", "--sse-kms-key-id", "--metadata", "--expected-size", "--grants", "--source-region",
             "--expires"}
AWS_LOCAL = {"configure", "help", "history", "sso", "login", "logout"}
ACCOUNT = re.compile(r"arn:aws[\w-]*:[\w-]*:[\w-]*:(\d{12}):|\"Account\"\s*:\s*\"(\d{12})\"")
# Without --with-decryption a parameter read shows no SecureString value.
SSM_READS = {"SSM.GetParameter", "SSM.GetParameters", "SSM.GetParametersByPath"}
VERB_IMPACT = re.compile(r"^(Delete|Terminate|Remove|Purge|Destroy)")
# Skipping the recovery window deletes a secret for good.
SECRET_PURGED = {"source": "own", "id": "secret-deleted-for-good", "tactic": "Impact", "severity": "high"}
S3_HIGH_LEVEL = {"rm": "DeleteObject", "rb": "DeleteBucket", "mb": "CreateBucket", "ls": "ListObjectsV2",
                 "presign": "GetObject", "website": "PutBucketWebsite"}


def accounts_in(text):
    return {a or b for a, b in ACCOUNT.findall(text)}


def sdk_service(cli):
    if cli in ("s3", "s3api"):
        return "S3"
    found = AWS["sdk_by_norm"].get(re.sub(r"[^a-z0-9]", "", cli.lower()))
    if found:
        return found
    candidates = AWS["sdk_by_prefix"].get(cli, [])
    return candidates[0] if len(candidates) == 1 else None


def aws_call(argv):
    """(cli service, operation, SDK method, profile) of an `aws` command."""
    profile = option(argv, "--profile")
    rest = positional(argv[1:], AWS_GLOBAL_VALUED)
    if len(rest) < 2 or rest[0] in AWS_LOCAL:
        return None
    service, op = rest[0], rest[1]
    if service == "s3":
        if op in ("cp", "sync", "mv"):
            # `-` is standard input or output.
            tail = ["stdio" if a == "-" else a for a in argv[argv.index(op) + 1:]]
            args = positional(tail, AWS_GLOBAL_VALUED | S3_VALUED)
            down = len(args) >= 2 and args[0].startswith("s3://") and not args[-1].startswith("s3://")
            api = "GetObject" if down else "PutObject"
        else:
            api = S3_HIGH_LEVEL.get(op)
    else:
        api = "".join(w[:1].upper() + w[1:] for w in op.split("-"))
    sdk = sdk_service(service)
    method = f"{sdk}.{api}" if sdk and api else None
    return service, op, method, profile


def aws_access(method, op):
    """"read" or "change", by the method's IAM access level, else the CLI verb."""
    code = AWS["methods"].get(method or "")
    if code:
        return "read" if code in ("L", "R") else "change"
    reads = re.match(r"^(describe|get|list|head|ls|presign|wait|lookup|search|scan|query|select)", op)
    return "read" if reads else "change"


# The only settings kept from ~/.aws/config, each checked against its format.
# Every other line, credentials included, is dropped as it is read.
AWS_KEEP = {
    "sso_account_id": re.compile(r"^\d{12}$"),
    "role_arn": re.compile(r"^arn:aws[\w-]*:iam::\d{12}:role/[\w+=,.@/-]+$"),
    "source_profile": re.compile(r"^[\w.@+-]+$"),
}


def aws_profiles(home):
    """Profile name -> account, following `source_profile`. A value keeps only
    its first word; indented nested settings are skipped."""
    path = os.path.join(home, ".aws", "config")
    raw, section = {}, None
    if not inside(path):
        ERRORS["files_skipped"] += 1
        return {}
    opened = open_owned(path, 16 * SMALL_MAX)
    if not opened:
        return {}
    with opened[0] as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped[0] in "#;" or line[:1] in (" ", "\t"):
                continue
            if stripped.startswith("["):
                name = stripped[1:].split("]", 1)[0].strip()
                if name.startswith(("sso-session ", "services ")):
                    section = None
                else:
                    section = name[len("profile "):].strip() if name.startswith("profile ") else name
                continue
            if section is None or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key, value = key.strip().lower(), (value.split() or [""])[0]
            if key in AWS_KEEP and AWS_KEEP[key].match(value):
                raw.setdefault(section, {})[key] = value
    accounts = {}
    for name, values in raw.items():
        seen, current, account = set(), values, ""
        while current is not None and id(current) not in seen and not account:
            seen.add(id(current))
            account = current.get("sso_account_id", "") or (
                current["role_arn"].split(":")[4] if "role_arn" in current else "")
            current = raw.get(current.get("source_profile", ""))
        if account:
            accounts[name] = account
    return accounts


# --- Code repositories ---

REPO_URL = re.compile(r"(?:https?://|ssh://)?(?:[\w.-]+@)?([\w.-]+\.[a-z]{2,})[:/]([\w.-]+)/([\w.-]+?)"
                      r"(?:\.git)?/?$")
GH_WRITE_VERBS = {"create", "merge", "close", "edit", "comment", "review", "ready", "reopen", "delete",
                  "transfer", "lock", "unlock", "upload", "rename", "archive", "unarchive", "set", "remove",
                  "run", "rerun", "cancel", "enable", "disable", "sync", "fork", "add"}
# Comments, reviews, reactions, labels and issues: the conversation around
# code, kept apart from changes to it. An approving review is a change.
GH_CONVERSATION = re.compile(r"^/?repos/[^/]+/[^/]+/(issues|labels|comments|(pulls|issues)/comments"
                             r"|pulls/\d+/(comments|reviews|requested_reviewers)|[\w/-]*/(reactions|replies))(/|\?|$)")
GH_REPO_GROUPS = {"pr", "issue", "release", "run", "workflow", "secret", "variable", "label", "cache",
                  "ruleset", "repo"}
_REMOTES = {}


def repo_name(url):
    match = REPO_URL.search(url.strip().strip("'\""))
    if not match:
        return None
    host, owner, name = match.groups()
    return f"{owner}/{name}" if host == "github.com" else f"{host}/{owner}/{name}"


def git_dirs(folder):
    """(git folder, common git folder) of the repository holding a folder,
    following a worktree's `.git` file, or None. Only folders in the user's
    home are read."""
    if not inside(folder):
        return None
    here = os.path.realpath(folder)
    while inside(here):
        dot = os.path.join(here, ".git")
        if os.path.isdir(dot) and not os.path.islink(dot):
            return dot, dot
        if os.path.isfile(dot):
            pointer = (read_small(dot) or "").split("gitdir:", 1)
            gitdir = os.path.normpath(os.path.join(here, pointer[1].strip())) if len(pointer) > 1 else None
            if not gitdir or not inside(gitdir):
                return None
            named = os.path.join(gitdir, "commondir")
            common = os.path.isfile(named) and read_small(named)
            common = os.path.normpath(os.path.join(gitdir, common.strip())) if common else gitdir
            return (gitdir, common) if inside(common) else None
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return None


def remotes_of(folder):
    """Remote name -> repository for the repository holding a folder."""
    folder = os.path.abspath(folder)
    if folder in _REMOTES:
        return _REMOTES[folder]
    found, dirs = {}, git_dirs(folder)
    if dirs:
        parser = configparser.RawConfigParser(strict=False)
        try:
            parser.read_string(read_small(os.path.join(dirs[1], "config")) or "")
        except configparser.Error:
            pass
        for section in parser.sections():
            named = re.match(r'remote "(.+)"', section)
            if named and parser.has_option(section, "url"):
                repo = repo_name(parser.get(section, "url")[:TEXT_MAX])
                if repo:
                    found[named.group(1)] = repo
    _REMOTES[folder] = found
    return found


def symbolic_ref(path, prefix):
    """The branch a symbolic ref file (`ref: refs/heads/main`) names, or None."""
    match = re.match(r"ref:\s*" + re.escape(prefix) + r"(\S+)\s*$", read_small(path) or "")
    return match.group(1) if match else None


def git_verb(argv, folder):
    """(index of git's command, folder it runs in, after `-C`)."""
    i, here = 1, folder
    while i < len(argv) and argv[i].startswith("-"):
        if argv[i] in ("-C", "-c") and i + 1 < len(argv):
            if argv[i] == "-C":
                here = os.path.abspath(os.path.join(here, expand(argv[i + 1], {"HOME": OWNER["given"]})))
            i += 2
            continue
        i += 1
    return i, here


PUSH_VALUED = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
PROTECTED_BRANCH = re.compile(r"^(main|master|trunk|develop|prod|production|release([-/].*)?)$")
FORCE_PUSH = {tier: {"source": "own", "id": "force-push:" + tier, "tactic": "Impact", "severity": severity}
              for tier, severity in (("default-branch", "high"), ("branch", "medium"),
                                     ("branch-with-lease", "low"), ("unnamed", "medium"),
                                     ("unnamed-with-lease", "low"),
                                     ("default-branch-with-lease", "high"))}


def force_push(argv, folder):
    """The FORCE_PUSH tier of a `git push` that may overwrite remote history,
    by the branch it targets; the worst one when it names several."""
    i, here = git_verb(argv, folder)
    if argv[i:i + 1] != ["push"]:
        return None
    options = [a for a in argv[i + 1:] if a.startswith("-")]
    if any(a in ("--delete", "--mirror") or re.match(r"^-[a-zA-Z]*d", a) for a in options):
        return None
    plain = any(a == "--force" or re.match(r"^-[a-zA-Z]*f", a) for a in options)
    lease = any(a.startswith(("--force-with-lease", "--force-if-includes")) for a in options)
    rest = positional(argv[i + 1:], PUSH_VALUED)
    if rest and re.match(r"^(\.{0,2}/|~|file://)", rest[0]):
        # A repository in a folder on this machine holds no shared history.
        return None
    refspecs = [r for r in rest[1:] if not r.startswith(":")]
    if not (plain or lease or any(r.startswith("+") for r in refspecs)):
        return None
    dirs = git_dirs(here)
    current = symbolic_ref(os.path.join(dirs[0], "HEAD"), "refs/heads/") if dirs else None
    remote = rest[0] if rest and re.match(r"^[\w.-]+$", rest[0]) else "origin"
    default = symbolic_ref(os.path.join(dirs[1], "refs", "remotes", remote, "HEAD"),
                           f"refs/remotes/{remote}/") if dirs else None
    tiers = []
    for spec in refspecs or ["HEAD"]:
        branch = re.sub(r"^refs/heads/", "", spec.lstrip("+").split(":")[-1])
        branch = current if branch == "HEAD" else branch
        if not branch:
            tiers.append("unnamed" if plain or spec.startswith("+") else "unnamed-with-lease")
        elif PROTECTED_BRANCH.match(branch) or branch == default:
            tiers.append("default-branch" if plain or spec.startswith("+") else "default-branch-with-lease")
        else:
            tiers.append("branch" if plain or spec.startswith("+") else "branch-with-lease")
    return FORCE_PUSH[min(tiers, key=lambda t: SEVERITY_RANK[FORCE_PUSH[t]["severity"]])]


REMOTE_DELETED = {"branch": {"source": "own", "id": "remote-branch-deleted", "tactic": "Impact", "severity": "low"},
                  "protected": {"source": "own", "id": "remote-default-branch-or-tag-deleted", "tactic": "Impact",
                                "severity": "medium"}}
TAG_NAME = re.compile(r"^(refs/tags/|v?\d+(\.\d+)+)")


def remote_deletion(argv, folder):
    """The REMOTE_DELETED rule of a `git push` that deletes a remote branch or tag: a branch
    is mostly cleanup after a merge; the default, a release or protected branch, or a tag isn't."""
    i, here = git_verb(argv, folder)
    if argv[i:i + 1] != ["push"]:
        return None
    rest = positional(argv[i + 1:], PUSH_VALUED)
    deleting = any(a == "--delete" or re.match(r"^-[a-zA-Z]*d", a) for a in argv[i + 1:] if a.startswith("-"))
    targets = rest[1:] if deleting else [r[1:] for r in rest[1:] if r.startswith(":") and len(r) > 1]
    if not targets:
        return None
    dirs = git_dirs(here)
    remote = rest[0] if re.match(r"^[\w.-]+$", rest[0]) else "origin"
    default = symbolic_ref(os.path.join(dirs[1], "refs", "remotes", remote, "HEAD"),
                           f"refs/remotes/{remote}/") if dirs else None
    protected = any(TAG_NAME.match(t) or PROTECTED_BRANCH.match(re.sub(r"^refs/heads/", "", t))
                    or re.sub(r"^refs/heads/", "", t) == default for t in targets)
    return REMOTE_DELETED["protected" if protected else "branch"]


def git_touch(argv, folder):
    """(repo, "read" | "write") for a git command that reaches a remote."""
    i, here = git_verb(argv, folder)
    if i >= len(argv):
        return None
    verb = argv[i]
    rest = positional(argv[i + 1:], {"-o", "--push-option", "--depth", "-b", "--branch", "--origin"})
    if verb not in ("push", "pull", "fetch", "clone", "ls-remote"):
        return None
    if verb == "clone":
        repo = next((repo_name(a) for a in rest if repo_name(a)), None)
    else:
        remotes = remotes_of(here)
        repo = remotes.get(rest[0]) if rest and rest[0] in remotes else remotes.get("origin")
        if not repo and rest:
            repo = repo_name(rest[0])
    return (repo, "write" if verb == "push" else "read") if repo else None


def gh_touch(argv, folder):
    """(repo, "read" | "write" | "conversation") for a gh command about a repository."""
    if len(argv) < 2:
        return None
    group, verb = argv[1], (argv[2] if len(argv) > 2 else "")
    given = option(argv, "-R", "--repo")
    repo = given if given and "/" in given else None
    if group == "api":
        path = next((re.search(r"^/?repos/([\w.-]+)/([\w.-]+)", a) for a in argv[2:]
                     if re.search(r"^/?repos/", a)), None)
        method = (option(argv, "-X", "--method") or "").upper()
        if not method:
            fields = any(a in ("-f", "-F", "--field", "--raw-field", "--input") for a in argv)
            method = "POST" if fields else "GET"
        if path:
            repo = f"{path.group(1)}/{path.group(2)}"
        if not repo:
            return None
        if method in ("GET", "HEAD"):
            return repo, "read"
        endpoint = next((a for a in argv[2:] if re.search(r"^/?repos/", a)), "")
        talk = GH_CONVERSATION.search(endpoint) and not (
            "/reviews" in endpoint and any("APPROVE" in a for a in argv))
        return repo, "conversation" if talk else "write"
    if group == "repo" and verb in ("view", "clone", "delete", "edit", "rename", "archive", "fork"):
        named = next((a for a in positional(argv[3:], {"-R", "--repo"}) if "/" in a), None)
        repo = repo or (repo_name("https://github.com/" + named) if named else None)
    if group in GH_REPO_GROUPS and not repo and not (group == "repo" and verb in ("create", "list")):
        repo = remotes_of(folder).get("origin")
    if not repo:
        return None
    if verb not in GH_WRITE_VERBS:
        return repo, "read"
    talk = group in ("issue", "label") or (group, verb) == ("pr", "comment") \
        or (group, verb) == ("pr", "review") and not any(a in ("--approve", "-a") for a in argv) \
        or (group, verb) == ("pr", "edit") and not any(a in ("--base", "-B") or a.startswith("--base=") for a in argv)
    return repo, "conversation" if talk else "write"


# --- Other resources ---

AZ_SKIP = {"login", "logout", "account", "config", "version", "extension", "upgrade", "find", "interactive",
           "init", "bicep"}
GCLOUD_SKIP = {"auth", "config", "components", "info", "version", "help", "init", "topic", "survey",
               "feedback"}
CLOUD_READ = re.compile(r"^(show|list|get|describe|exists|query|wait|download|read|search|print|check|browse"
                        r"|tail|ls$|cat$|logs?$|ssh$|scp$)")
KUBE_READ = {"get", "describe", "logs", "top", "explain", "api-resources", "api-versions", "cluster-info",
             "auth", "events", "wait", "diff", "version", "port-forward", "proxy"}
KUBE_VALUED = {"--context", "-n", "--namespace", "-o", "--output", "-l", "--selector", "-f", "--filename",
               "-c", "--container"}
KUBE_SKIP = {"config", "completion", "plugin", "kustomize", "options", "help", "version"}
LOCAL_HOST = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\]|[\w.-]+\.localhost)$", re.I)
# A name left for the reader to fill in: `$PROJECT`, `<project>`, `YOUR_PROJECT`.
PLACEHOLDER = re.compile(r"[$`<>{}]|(?i:redacted|^your[_-]|(^|[-_.])x{3,}([-_.]|$))"
                         r"|^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")


def local_network(host):
    """Whether a host is this machine or on its local network, where data sent stays inside."""
    if LOCAL_HOST.match(host) or re.search(r"\.(local|internal)$", host, re.I):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local
# A name with a top-level domain or an IP address, so a templated URL
# (`https://www.[REDACTED]`) names no host.
URL = re.compile(r"^https?://((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?=[:/?#]|$)")
SSH_VALUED = {"-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-m", "-O", "-Q",
              "-S", "-W", "-w", "-P"}
CURL_VALUED = {"-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
               "--data-urlencode", "-F", "--form", "-o", "--output", "-u", "--user", "-A", "--user-agent",
               "-e", "--referer", "-m", "--max-time", "-w", "--write-out", "-T", "--upload-file", "--json",
               "-x", "--proxy", "--connect-timeout", "-b", "--cookie", "-c", "--cookie-jar", "--retry", "-K",
               "--config"}
CURL_SENDS = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "-T",
              "--upload-file", "--json", "--post-data", "--post-file"}


def named(name, unnamed):
    """The resource a command names, or `unnamed` when it names none or a placeholder."""
    return name if name and not PLACEHOLDER.search(name) else unnamed


def cloud_verb(argv, skip):
    """The command words of an `az` or `gcloud` command (`storage blobs list`), up to the first
    option or argument; None for one that reaches no cloud."""
    words = []
    for word in argv[1:]:
        if not re.match(r"^[a-z][a-z0-9-]*$", word):
            break
        if word not in ("alpha", "beta"):
            words.append(word)
    if not words or words[0] in skip:
        return None
    return words


def cloud_mode(words, argv=()):
    """"read" when a command word reads (`show`, `list`, `logs`, `ssh`); `az rest` reads
    unless it sends a body or a method that writes."""
    if words[:1] == ["rest"]:
        method = (option(argv, "--method", "-m") or "get").lower()
        return "change" if method in ("post", "put", "patch", "delete") or option(argv, "--body", "-b") \
            else "read"
    return "read" if any(CLOUD_READ.match(w) for w in words) else "change"


# MCP servers that run on the laptop (a browser, the file system, the screen,
# a code index) rather than a SaaS tool, by name: what they change is no asset.
LOCAL_MCP = re.compile(r"(?i)playwright|puppeteer|chrome|browser|preview|filesystem|computer[-_]?use"
                       r"|desktop|^ide$|^acp$|context-mode|serena|sequential-?thinking|simulator|devtools"
                       r"|repomix|memory|codegraph|local|ccd_session|^codex$|paper|deepwork")
MCP_SERVERS = [(re.compile(r["match"], re.I),
                {t.lower(): mode for mode in ("read", "change") for t in r[mode]}) for r in MCP["servers"]]
MCP_VERBS = {verb: mode for mode in ("read", "change") for verb in MCP["verbs"][mode]}
SQL_WRITE = re.compile(r"(?i)\b(insert|update|delete|merge|upsert|create|alter|drop|truncate|grant|revoke)\b")


def mcp_access(server, tool, args):
    """"read", "change" or "call" (unclassified) for an MCP tool call: by the
    server's listed tools, the SQL it runs, else the first verb in its name."""
    name = tool.lower()
    if name in MCP["sql"]:
        sql = next((v for k, v in args.items() if k in ("query", "sql") and isinstance(v, str)), None)
        return "call" if sql is None else "change" if SQL_WRITE.search(sql[:TEXT_MAX]) else "read"
    listed = next((tools[name] for match, tools in MCP_SERVERS
                   if match.search(server) and name in tools), None)
    if listed:
        return listed
    words = [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", tool)]
    for i, word in enumerate(words):
        if word in MCP_VERBS:
            after = words[i + 1] if i + 1 < len(words) else ""
            return MCP_VERBS[after] if word in MCP["defer"] and after in MCP_VERBS else MCP_VERBS[word]
    return "call"


def web_host(url):
    """The host a URL names, unless it is local or a placeholder."""
    match = URL.match(url)
    if match and not local_network(match.group(1)) and not PLACEHOLDER.search(match.group(1)):
        return match.group(1).lower()
    return None


def web_touch(argv):
    """(host, "read" | "send") for each URL a curl or wget command names."""
    method = (option(argv, "-X", "--request", "--method") or "").upper()
    sends = method not in ("", "GET", "HEAD") or any(a.split("=", 1)[0] in CURL_SENDS for a in argv)
    hosts = {web_host(arg) for arg in positional(argv[1:], CURL_VALUED)} - {None}
    return [(h, "send" if sends else "read") for h in sorted(hosts)]


def fetch_url(argv):
    """The URL a fetch reads, "" when it is built at run time, None for a
    `wget` that writes to a file."""
    to_stdout = re.search(r"\s(-\w*O\s?-|--output-document[= ]-)(\s|$)", " ".join(argv))
    if os.path.basename(argv[0]) == "wget" and not to_stdout:
        return None
    args = positional(argv[1:], CURL_VALUED | {"-O", "--output-document"})
    args += (option(argv, "-Uri") or "").split()
    url = next((a for a in args if "://" in a), None) or next(iter(args), "")
    return "" if re.search(r"[$`]", url) else url


def piped_run(piece):
    """The URL whose content a segment runs: fetched and piped into a shell or
    interpreter, or substituted into one."""
    if not FETCH_NAMED.search(piece):
        return None
    sub = SUBSTITUTED.search(piece)
    if sub:
        return fetch_url(words(sub.group("fetch"), {}))
    stages = [words(s, {}) for s in split_command(piece)]
    fetch = next((i for i, argv in enumerate(stages) if argv and os.path.basename(argv[0]) in FETCHERS), None)
    if fetch is None:
        return None
    url = fetch_url(stages[fetch])
    # An API query's answer piped into python is data, not a script.
    query = any("?" in a for a in positional(stages[fetch][1:], CURL_VALUED))
    if url is not None and any(argv and PIPED_INTO.match(os.path.basename(argv[0])) and reads_stdin(argv)
                               and not (query and INTERPRETER_NAME.match(os.path.basename(argv[0])))
                               for argv in stages[fetch + 1:]):
        return url
    return None


def reads_stdin(argv):
    """Whether a shell or interpreter runs what it reads on standard input:
    given no script, `-c`, `-m`, `-e` or input of its own; `-s` and `-` say so."""
    shell = re.match(r"^((ba|z|da|k|fi)?sh)$", os.path.basename(argv[0]))
    # Its input is a file or a heredoc (`curl … | python3 - <<EOF`), not the pipe.
    if any(re.match(r"^\d*<(?!\()", a) for a in argv[1:]):
        return False
    for arg in argv[1:]:
        if arg == "-" or (shell and re.match(r"^-\w*s", arg)):
            return True
        if re.match(r"^\d*<", arg):
            return False
        if re.match(r"^(\d*>|&>)", arg) or arg == "--":
            continue
        if arg.startswith("-"):
            if re.match(r"^-\w*c" if shell else r"^-[cmep]|^--(eval|print)", arg):
                return False
            continue
        return False
    return True


def under(host, hosts):
    return any(host == h or host.endswith("." + h) for h in hosts)


def source_tier(url, text, folder, own):
    """"pinned", "unpinned" or "unknown" for the code at a URL. Known: an
    installer from its official host and path, or a code host repository of a
    listed organisation, of an owner of a repository in `own` or of the
    folder's remote. Pinned: the command names a version or commit."""
    url = re.sub(r"^git\+", "", re.sub(r"^github:", "https://github.com/", url))
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return "unknown"
    if parts.scheme not in ("https", "ssh") or not host or under(host, KNOWN["unknown_hosts"]):
        return "unknown"
    try:
        ipaddress.ip_address(host)
        return "unknown"
    except ValueError:
        pass
    where = (host + (parts.path or "/")).lower()
    segments = [s for s in re.split(r"[/@]", parts.path) if s]
    segments += [parts.fragment] if "=" not in parts.fragment else []
    ref = host in CODE_HOSTS and ("tags" in segments[2:-1] or any(
        VERSION_REF.match(re.sub(r"\.(zip|tar\.gz|tgz|git)$", "", s)) for s in segments[2:]))
    for row in INSTALLERS:
        if any(where == u or where.startswith(u if u[-1] in "/._" else u + "/") for u in row["url"]):
            return "pinned" if ref or (row["pinned"] and row["pinned"].search(text)) else "unpinned"
    if host in CODE_HOSTS and segments:
        owner = segments[0].lower()
        family = CODE_HOSTS[host]
        owners = {(r if r.count("/") == 2 else "github.com/" + r).rsplit("/", 1)[0].lower()
                  for r in set(own) | set(remotes_of(folder).values())}
        if owner in KNOWN["code_host_owners"].get(family, ()) or f"{family}/{owner}" in owners:
            return "pinned" if ref else "unpinned"
    return "unknown"


def upload(argv):
    """The host a curl or wget command uploads a local file to, if it does:
    sent whole (-T) or as a form's file (-F f=@path). A request body read
    from a file (-d @body.json) is not a file upload."""
    args = argv[1:]
    files = any(a in ("-T", "--upload-file", "--post-file")
                or a.startswith(("--upload-file=", "--post-file=")) for a in args) \
        or any(a in ("-F", "--form") and re.search(r"=[@<]", b) for a, b in zip(args, args[1:])) \
        or any(a.startswith("--form=") and re.search(r"=[@<]", a[7:]) for a in args)
    if not files:
        return None
    return next((h for h, _ in web_touch(argv)), None)


def ssh_hosts(argv):
    if argv[0] == "ssh":
        targets = positional(argv[1:], SSH_VALUED)[:1]
    else:
        targets = [a for a in positional(argv[1:], SSH_VALUED | {"-e", "--rsh"})
                   if re.match(r"^[\w.@-]+:", a) and "://" not in a]
    hosts = set()
    for target in targets:
        host = target.split(":", 1)[0].split("@")[-1]
        if re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*$", host) and not LOCAL_HOST.match(host) \
                and not PLACEHOLDER.search(host):
            hosts.add(host)
    return sorted(hosts)


def registry_of(argv):
    """The registry a publish or push goes to."""
    program, rest = argv[0], argv[1:]
    if program in PUBLISHERS and rest[:1] == [PUBLISHERS[program][0]]:
        _, flag, default = PUBLISHERS[program]
        match = URL.match(option(argv, flag) or "") if flag else None
        return match.group(1) if match else default
    if program in ("docker", "podman") and rest[:1] == ["push"]:
        image = next(iter(positional(rest[1:])), "")
        first = image.split("/", 1)[0]
        named = "/" in image and ("." in first or ":" in first or first == "localhost")
        return first if named else "docker.io"
    return None


# --- Secret files ---

# Programs whose first argument is a pattern or a script.
PATTERN_FIRST = {"grep", "rg", "awk", "sed"}
PATTERN_VALUED = GREP_VALUED | {"-g", "--glob", "-t", "--type"}
# Programs that take a whole file rather than look something up in it.
WHOLE_FILE = {"cat", "less", "more", "head", "tail", "bat", "base64", "xxd", "od", "strings", "cp", "scp",
              "rsync", "open", "zip", "tar", "gpg", "curl"}
READERS = WHOLE_FILE | PATTERN_FIRST | {"source", ".", "jq", "find", "fd", "locate"}
# Credential files the safety-net list leaves out (shell history included).
MORE_SECRET_NAMES = {".bash_history", ".zsh_history", ".history", ".sh_history", ".mysql_history",
                     ".psql_history", ".python_history", ".node_repl_history", ".vault-token", ".pgpass",
                     ".my.cnf", "terraform.tfstate", "shadow", "gshadow", "sudoers"}
MORE_SECRET_EXTENSIONS = {"tfvars", "tfstate"}
MORE_SECRET_HOME = (".azure", ".oci", ".gnupg", ".config/gcloud")
# Files under a credentials folder that hold none.
NOT_SECRET = {"known_hosts", "known_hosts.old", "authorized_keys", "config", "environment", "go.env",
              "gpg.conf", "gpg-agent.conf", "dirmngr.conf", "scdaemon.conf", "common.conf"}
# A file named for a key or token by a whole word (not `tokenizer.json`),
# with no extension or a plain one. A JSON file is mostly settings, so only
# names tools give their credentials count.
KEY_NAME = re.compile(r"api[_-]?key|(^|[._-])(token|secrets?|credentials?|passwords?)([._-]|$)", re.I)
KEY_EXTENSIONS = {"", "txt", "key", "token"}
# Test data, templates and git's credential helpers (git-credential-env).
NOT_KEY_NAME = re.compile(r"(?i)test|example|sample|template|fixture|mock|dummy|fake|^git-credential-")
KEY_JSON = re.compile(r"^(credentials|client_secrets?[\w.-]*|service[_-]?account[\w.-]*)\.json$", re.I)
# Code and docs named for credentials (credentials-cli.test.ts) hold none.
SOURCE_EXTENSIONS = {"py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "go", "rs", "java", "kt", "rb", "php",
                     "cs", "swift", "c", "h", "cc", "cpp", "md", "mdx", "html", "css", "snap"}
SECRET_EXT_PATTERNS = [re.compile(p) for p in SECRETS["extension_patterns"]]
SECRET_NAME_PATTERNS = [re.compile(p) for p in SECRETS["basename_patterns"]]


@functools.lru_cache(maxsize=1024)
def secret_file(path, home, whole=True):
    """The safety-net rule a path falls under, if it holds secrets. Coding
    tools' config files count only when read whole."""
    path = path.lstrip("@").replace("\\", "/")
    # Not a file: a URL, a query, a key=value argument, a JSON body.
    if "://" in path or "?" in path or "&" in path \
            or (re.match(r"^[\w.-]+=", path) and "/" not in path.split("=")[0]) \
            or re.search(r"[\s{}\"'<>|;]", path):
        return None
    if re.match(r"^[A-Za-z]:/", path):
        path = path[2:]
    full = home + path[1:] if path.startswith("~") else path
    base = os.path.basename(full)
    relative = os.path.relpath(full, home) if full.startswith(home + os.sep) else None
    if relative in SECRETS["home_paths"]:
        return "~/" + relative
    if not base or base in NOT_SECRET or base.endswith((".pub", "_known_hosts")) or "/.ssh/config.d/" in full:
        return None
    if base in SECRETS["basenames"] or base in MORE_SECRET_NAMES:
        return base
    env = SECRETS["env_variant"]
    if (base.startswith(env["prefix"]) and not any(base.endswith(s) for s in env["not_suffixes"])
            and not any(base.startswith(p) for p in env["not_prefixes"]) and base not in env["not_names"]):
        return ".env.*"
    if base.endswith(".env") and not NOT_KEY_NAME.search(base):
        return "*.env"
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    for prefix in SECRETS["variant_prefixes"]:
        rest = base[len(prefix):]
        if base.startswith(prefix) and (rest[:1] in ("-", "_") and ext.lower() not in SOURCE_EXTENSIONS
                                        or rest in SECRETS["variant_dot_suffixes"]):
            return prefix + "*"
    # A .pem is as often a certificate: it counts when named for a key, or in ~/.ssh.
    if ext and (ext in SECRETS["extensions"] or ext in MORE_SECRET_EXTENSIONS
                or any(p.search(ext) for p in SECRET_EXT_PATTERNS)) \
            and (ext != "pem" or "key" in base.lower()):
        return "*." + ext
    if any(p.search(base) for p in SECRET_NAME_PATTERNS):
        return base
    if relative:
        for prefix in list(SECRETS["home_paths"]) + list(MORE_SECRET_HOME):
            if relative == prefix or relative.startswith(prefix + "/"):
                return "~/" + prefix
    if whole:
        # Claude Code's local settings hold permissions, not credentials.
        for listed in SECRETS["coding_cli_paths"]:
            if expand(listed, {"HOME": home}) == full and not listed.endswith("/settings.local.json"):
                return listed
    if (KEY_JSON.match(base) or KEY_NAME.search(base) and ext.lower() in KEY_EXTENSIONS) and "*" not in base \
            and not NOT_KEY_NAME.search(base):
        return "key file"
    return None


def secret_read(argv, home, folder="/"):
    """The secret file a reading command reads, if any; a relative path is taken from
    the folder it runs in, when that is known."""
    # An output redirect's target is written, not read; it may sit anywhere
    # (`find … 2>/dev/null -exec cp {} …`).
    program, args, target = argv[0], [], False
    for a in argv[1:]:
        if target or re.match(r"^\d*(>|&>)", a):
            target = not target and bool(REDIRECT_ALONE.match(a))
            continue
        args.append(a)
    if program == "sed" and any(a == "-i" or a.startswith("-i") for a in args):
        return None
    if program == "scp":
        # The key it signs in with (-i) and its config (-F) are not sent.
        args = positional(args, SSH_VALUED)
    if program in ("cp", "scp", "rsync") and len(positional(args)) > 1:
        # The last path is written, not read.
        last = positional(args)[-1]
        args = args[:len(args) - 1 - args[::-1].index(last)]
    # A grep that prints no line (`-q`, `-c`, `-l`, `-L`) shows whether a file
    # holds something, not what. rg's `-L` follows links.
    quiet = r"^-[a-zA-Z]*[qcl%s]" % ("L" if program == "grep" else "")
    if program in ("grep", "rg") and any(a in ("--quiet", "--silent", "--count", "--files-with-matches",
                                               "--files-without-match") or re.match(quiet, a) for a in args):
        return None
    if program in PATTERN_FIRST and not any(a in ("-e", "-f", "--regexp", "--file") for a in args):
        pattern = next(iter(positional(args, PATTERN_VALUED)), None)
        if pattern is not None:
            args.remove(pattern)
    if program in ("find", "fd", "locate"):
        # Finding a file reads nothing; `-exec cat` does. A name looked for
        # (`-path '*/.kube/config'`) is taken as in the home.
        runs = any(a in ("-exec", "-execdir", "-ok", "-okdir", "-x", "--exec", "-X", "--exec-batch")
                   for a in args)
        if not runs or program == "locate":
            return None
        names = ["~/" + args[i + 1].lstrip("*/") for i, a in enumerate(args[:-1])
                 if a in ("-name", "-iname", "-path", "-wholename", "-ipath")]
        starts = args[:next((i for i, a in enumerate(args) if a.startswith(("-", "(", "!"))), len(args))]
        args = names + starts if program == "find" else args + [a.lstrip("*/") for a in args]
    elif program == "curl":
        # curl reads a file only when it sends one (`-d @f`, `-T f`).
        args = [a.split("@", 1)[1] for a in args if "@" in a[:1] or "=@" in a] \
            + [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-T", "--upload-file", "-K", "--config")]
    # A coding agent's settings count only when shown, not copied (a backup).
    whole = program in WHOLE_FILE and program != "cp"
    known = folder not in ("/", "") and program not in ("find", "fd", "locate")
    candidates = [os.path.normpath(os.path.join(folder, a)) if known and not a.startswith(("/", "~", "-", "<"))
                  and not re.match(r"^[A-Za-z]:\\", a) else a
                  for a in args if known or "/" in a or re.match(r"^[A-Za-z]:\\", a) or a.startswith(".")
                  or program in ("find", "fd", "locate")]
    # Terraform variables count only when read whole; an env file sourced
    # sets variables, it shows none.
    return next(((s, a) for a in candidates for s in [secret_file(a, home, whole)]
                 if s and (program in WHOLE_FILE or s != "*.tfvars")
                 and not (program in ("source", ".") and s.startswith((".env", "*.env")))), None)


HISTORY = re.compile(r"^\.\w*_?history$")
# A home's dot folders and files, any home's, and the system's password files.
PERSONAL = re.compile(r"^/(Users|home)/[^/]+/\.|^/(var/)?root/\.|^/etc/(g?shadow|sudoers)$")


def secret_rule(secret, path, home):
    """(finding, what) for reading a secret file: personal credentials (in a
    home's dot folders, High), shell history, a coding agent's settings, or a
    project's secrets (.env files wherever they are)."""
    path = re.sub(r"^[A-Za-z]:", "", path.lstrip("@").replace("\\", "/"))
    full = home + path[1:] if path.startswith("~") else path
    if HISTORY.match(secret):
        kind, severity = "shell-history", "medium"
    elif secret in SECRETS["coding_cli_paths"] and not re.search(r"(?i)auth|cred|token|secret|key", secret):
        # A coding agent's settings may hold a token, but mostly settings.
        kind, severity = "agent-settings", "low"
    elif (PERSONAL.match(full) or full.startswith(home.rstrip("/") + "/.")) \
            and not secret.startswith((".env", "*.env")):
        kind, severity = "personal-credentials", "high"
    else:
        kind, severity = "project-secrets", "low" if secret == "*.tfvars" else "medium"
    secret = secret if secret == "key file" else safe_name(secret, home)
    return {"source": "claude-code-safety-net", "id": kind + ":" + secret, "tactic": "Credential Access",
            "severity": severity}, "read " + secret


# --- Commands that hand control to other code ---

INTERPRETERS = {"python", "python3", "node", "bash", "sh", "zsh", "ruby", "perl", "bun", "deno", "tsx", "php"}
# A program run by its path from one of these is installed, not a script.
SYSTEM_BIN = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt/homebrew/bin"}
TASK_RUNNERS = {"make", "just", "task", "npx", "uvx", "bunx", "pipx", "invoke", "rake"}
# Tools a task runner often runs, counted as a build.
BUILD_TOOLS = {"tsc", "jest", "vitest", "mocha", "playwright", "pytest", "eslint", "prettier", "next", "vite",
               "webpack", "tsx"}
BUILDS = {"pytest", "cargo", "go", "jest", "vitest", "mvn", "gradle", "./gradlew", "gradlew", "dotnet",
          "swift", "xcodebuild", "tox", "nox", "mocha", "playwright"}
DEPLOYS = {"terraform": {"apply", "destroy"}, "tofu": {"apply", "destroy"}, "pulumi": {"up", "destroy"},
           "cdk": {"deploy", "destroy"}, "sam": {"deploy"}, "serverless": {"deploy"}, "sls": {"deploy"},
           "helm": {"install", "upgrade"}, "ansible-playbook": None}


def hidden_kind(argv, text, path):
    program, rest = argv[0], argv[1:]
    # Asking for a version or help, or checking syntax, runs nothing.
    if any(a in ("--version", "-V", "--help", "-h") for a in rest[:1]) or (
            program in SHELLS and "-n" in rest) or (
            program == "node" and any(a in ("-c", "--check") for a in rest)) or (
            program in ("python", "python3") and rest[:2] == ["-m", "py_compile"]):
        return None
    if program in INTERPRETERS:
        inline = ("-e", "-p", "--eval", "--print") if program in ("node", "bun", "deno") else None
        typed = any(a in inline for a in rest) if inline \
            else any(re.match(r"^-[a-zA-Z]*[ce]$", a) for a in rest)
        if typed or "<<heredoc" in text or "-" in rest:
            return "inline_code"
        if program in ("python", "python3") and rest[:1] == ["-m"]:
            return "builds_tests" if rest[1:2] in (["pytest"], ["unittest"]) else "scripts"
        return "scripts" if positional(rest) else None
    if re.match(r"^\.{0,2}/", path) and os.path.dirname(path) not in SYSTEM_BIN \
            and not program.endswith("gradlew"):
        return "scripts"
    if program in ("npm", "pnpm", "yarn", "bun"):
        if rest[:1] in (["run"], ["run-script"], ["start"], ["exec"], ["dlx"]):
            return "task_runners"
        if rest[:1] in (["test"], ["t"]):
            return "builds_tests"
    elif program == "uv" and rest[:1] == ["run"]:
        tests = positional(rest[1:])[:1] in (["pytest"], ["python"]) and "pytest" in rest
        return "builds_tests" if tests else "scripts"
    elif program in TASK_RUNNERS:
        named = positional(rest)[:1]
        return "builds_tests" if named and named[0] in BUILD_TOOLS else "task_runners"
    elif program in BUILDS:
        builds = program != "cargo" or rest[:1] in (["run"], ["test"], ["build"], ["bench"])
        return "builds_tests" if builds else None
    elif program in DEPLOYS:
        verbs = DEPLOYS[program]
        return "deploy_tools" if verbs is None or (rest and rest[0] in verbs) else None
    elif program in ("docker", "podman"):
        if rest[:1] in (["run"], ["exec"]) \
                or rest[:2] in (["compose", "up"], ["compose", "run"], ["compose", "exec"]):
            return "containers"
    # A CI pipeline a push starts runs elsewhere, so it is not counted here.
    return None


# --- Reading the logs ---


def session_logs(home):
    """The session logs under ~/.claude/projects, without following links."""
    root = os.path.join(home, ".claude", "projects")
    if not os.path.isdir(root):
        return []
    if not inside(root):
        ERRORS["files_skipped"] += 1
        return []
    found = []
    for folder, _, names in os.walk(root, followlinks=False):
        found += [os.path.join(folder, n) for n in names if n.endswith(".jsonl")]
    return sorted(found, key=lambda p: pathlib.PurePath(p).parts)


def read_user(home, days, fmt):
    """What one user's logs hold within the window: shell commands, the account
    IDs in the output of AWS commands, MCP calls, WebFetch URLs, sessions, Read
    paths and active days. A session is one session id: a subagent's log
    carries its parent's. Adds the log format's counts to `fmt`."""
    since = max(0, time.time() - days * 86400)
    since_iso = datetime.datetime.fromtimestamp(since, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    calls, aws_ids, outputs, mcp, fetches, sessions = [], set(), {}, collections.Counter(), [], set()
    seen, reads, days_active = set(), [], set()
    per = {}  # session -> its span, version, folders and counts
    for path in session_logs(home):
        opened = open_owned(path, FILE_MAX)
        if not opened:
            continue
        handle, info = opened
        with handle:
            if info.st_mtime < since:
                continue
            try:
                for line in lines_of(handle):
                    if not line.strip():
                        continue
                    fmt["entries"] += 1
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        entry = None
                    except RecursionError:
                        skip_entry(line)
                        continue
                    try:
                        message = entry.get("message") if isinstance(entry, dict) else None
                        content = message.get("content") if isinstance(message, dict) else None
                        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str) or (
                                entry["type"] in ("user", "assistant")
                                and not isinstance(content, (list, str))):
                            fmt["unparsed_entries"] += 1
                            continue
                        if "version" in entry:
                            fmt["claude_code_versions"][str(entry["version"])[:64]] += 1
                        if not isinstance(content, list):
                            continue
                        stamp = str(entry.get("timestamp", ""))
                        for block in content:
                            if not isinstance(block, dict):
                                continue
                            if block.get("type") == "tool_use" and stamp >= since_iso:
                                use, name = block.get("id"), str(block.get("name", ""))[:256]
                                args = block.get("input") if isinstance(block.get("input"), dict) else {}
                                if not isinstance(use, str):
                                    continue
                                # Other models' ids repeat (`Bash:0`); a resumed session's copy keeps
                                # the id, time and input of the call.
                                key = (use, stamp, hashlib.sha256(json.dumps(
                                    args, sort_keys=True, default=str).encode("utf-8", "replace")).digest())
                                if key in seen:
                                    continue
                                seen.add(key)
                                fmt["tool_uses"]["mcp" if name.startswith("mcp__") else name] += 1
                                session = str(entry.get("sessionId"))[:TEXT_MAX]
                                sessions.add(session)
                                one = per.setdefault(session, {"first": stamp, "last": stamp, "version": "",
                                                               "tools": collections.Counter(),
                                                               "folders": collections.Counter(),
                                                               "shell_commands": 0, "mcp_calls": 0, "web_fetches": 0})
                                one["first"], one["last"] = min(one["first"], stamp), max(one["last"], stamp)
                                if "version" in entry:
                                    one["version"] = str(entry["version"])[:64]
                                one["tools"]["mcp" if name.startswith("mcp__") else name] += 1
                                if entry.get("cwd"):
                                    one["folders"][str(entry["cwd"])[:TEXT_MAX]] += 1
                                if re.match(r"^\d{4}-\d\d-\d\d$", stamp[:10]):
                                    days_active.add(stamp[:10])
                                # Monitor runs a shell command in the background.
                                if name in ("Bash", "PowerShell", "Monitor") and args.get("command"):
                                    command = str(args["command"])[:COMMAND_MAX]
                                    cwd = str(entry.get("cwd") or "")[:TEXT_MAX]
                                    calls.append((stamp, command, cwd, session + "\n" + use, session))
                                    one["shell_commands"] += 1
                                    if re.search(r"(^|[;&|(\s`])aws\s", command):
                                        aws_ids.add(session + "\n" + use)
                                elif name.startswith("mcp__"):
                                    server, _, tool = name[5:].partition("__")
                                    mcp[(server, tool, session, mcp_access(server, tool, args))] += 1
                                    one["mcp_calls"] += 1
                                elif name == "WebFetch" and args.get("url"):
                                    fetches.append(str(args["url"])[:TEXT_MAX])
                                    one["web_fetches"] += 1
                                elif name == "Read" and args.get("file_path"):
                                    reads.append((str(args["file_path"])[:TEXT_MAX], session, stamp))
                            elif block.get("type") == "tool_result" and isinstance(block.get("tool_use_id"), str) \
                                    and str(entry.get("sessionId"))[:TEXT_MAX] + "\n" + block["tool_use_id"] in aws_ids:
                                text = block.get("content")
                                if isinstance(text, list):
                                    text = "\n".join(str(b.get("text", "")) for b in text
                                                     if isinstance(b, dict))
                                outputs[str(entry.get("sessionId"))[:TEXT_MAX] + "\n" + block["tool_use_id"]] = \
                                    accounts_in(str(text or "")[:20000])
                    except Exception:
                        ERRORS["calls_skipped"] += 1
            except OSError:
                ERRORS["files_skipped"] += 1
    calls.sort()
    return calls, outputs, mcp, sorted(fetches), sessions, sorted(reads), days_active, per


# --- Reading Codex's logs ---
# One rollout file per session. Newer Codex records an action as a completed
# item, older Codex as the model's tool call and, once run, an end event with
# the same call id. A call without an end event was tried, and counts.

CODEX_SHELLS = {"shell", "container.exec", "shell_command", "exec_command", "local_shell"}
# A command typed by the user (`!`), and input sent to a command already counted.
CODEX_NOT_AGENT = {"user_shell", "unified_exec_interaction"}
PATCH_RUN = re.compile(r"^\s*(cd\s+\S+\s*&&\s*)?apply_?patch\b")
AWS_RUN = re.compile(r"(^|[;&|(\s`])aws\s")


def codex_logs(home):
    """The rollout files under ~/.codex/sessions and ~/.codex/archived_sessions, without following links."""
    found = []
    for name in ("sessions", "archived_sessions"):
        root = os.path.join(home, ".codex", name)
        if not os.path.isdir(root):
            continue
        if not inside(root):
            ERRORS["files_skipped"] += 1
            continue
        for folder, _, names in os.walk(root, followlinks=False):
            found += [os.path.join(folder, n) for n in names if n.startswith("rollout-") and n.endswith(".jsonl")]
    return sorted(found, key=lambda p: pathlib.PurePath(p).parts)


def codex_script(command):
    """A Codex shell call's command line: the script given to a shell with -c, else its words joined.
    None when it isn't one; "" when it applied a patch."""
    if isinstance(command, str):
        script = command
    elif isinstance(command, list) and command and all(isinstance(w, str) for w in command):
        if os.path.basename(command[0]) in ("apply_patch", "applypatch"):
            return ""
        if len(command) == 3 and os.path.basename(command[0]) in SHELLS and SHELL_SCRIPT_FLAG.match(command[1]):
            script = command[2]
        else:
            script = " ".join(shlex.quote(w) for w in command[:4096])
    else:
        return None
    script = script[:COMMAND_MAX]
    return "" if PATCH_RUN.match(script) else script


def codex_folder(path):
    """A working folder as Codex writes it: a path, or a file:// URL."""
    if not isinstance(path, str):
        return ""
    path = path[:TEXT_MAX]
    if path.startswith("file://"):
        path = urllib.parse.unquote(urllib.parse.urlsplit(path).path)
    return path


def codex_output(output):
    """A tool's output as text, read only for the account IDs in an AWS command's."""
    if isinstance(output, dict):
        output = output.get("content", output.get("output"))
    if isinstance(output, list):
        output = "\n".join(str(b.get("text", ""))[:20000] for b in output[:100] if isinstance(b, dict))
    return output[:20000] if isinstance(output, str) else ""


def codex_mcp(server, tool):
    """(server, tool) of a Codex MCP call. ChatGPT's apps all come through one server,
    `codex_apps`, so the app is named as the server: `linear`, not `codex_apps`."""
    server, tool = str(server or "")[:256], str(tool or "")[:256]
    if server.startswith("codex_apps__"):
        return server[len("codex_apps__"):], tool.lstrip("_")
    if server == "codex_apps":
        app, _, rest = tool.partition(".") if "." in tool else tool.partition("_")
        if app and rest:
            return app, rest
    return server, tool


def mapping(value):
    return value if isinstance(value, dict) else {}


def codex_event(kind, payload):
    """(action, rank, call id, details) for an entry that records an agent's action, or None. Actions:
    command, patch, mcp, web, tool; rank 0 is a completed item, 1 an end event, 2 the model's tool call."""
    what = payload.get("type")
    if kind == "event_msg" and what == "item_completed":
        item = mapping(payload.get("item"))
        it, use = item.get("type"), item.get("id")
        if it == "CommandExecution" and item.get("source") not in CODEX_NOT_AGENT:
            return "command", 0, use, {"command": item.get("command"), "cwd": item.get("cwd"),
                                       "output": item.get("aggregated_output")}
        if it == "McpToolCall":
            return "mcp", 0, use, {"server": item.get("server"), "tool": item.get("tool"),
                                   "args": item.get("arguments")}
        if it == "FileChange":
            return "patch", 0, use, {}
        if it == "WebSearch" or (it == "Extension" and item.get("kind") == "web.search"):
            return "web", 0, use, {"action": item.get("action")}
        if it == "DynamicToolCall":
            return "tool", 0, use, {"name": item.get("tool")}
        return None
    if kind == "event_msg":
        use = payload.get("call_id")
        if what == "exec_command_end" and payload.get("source") not in CODEX_NOT_AGENT:
            return "command", 1, use, {"command": payload.get("command"), "cwd": payload.get("cwd"),
                                       "output": payload.get("aggregated_output")}
        if what == "mcp_tool_call_end":
            call = mapping(payload.get("invocation"))
            return "mcp", 1, use, {"server": call.get("server"), "tool": call.get("tool"),
                                   "args": call.get("arguments")}
        if what == "patch_apply_end":
            return "patch", 1, use, {}
        if what == "web_search_end":
            return "web", 1, use, {"action": payload.get("action")}
        return None
    if kind != "response_item":
        return None
    use = payload.get("call_id") or payload.get("id")
    if what == "local_shell_call":
        action = mapping(payload.get("action"))
        return "command", 2, use, {"command": action.get("command"), "cwd": action.get("working_directory")}
    if what == "web_search_call":
        return "web", 2, use, {"action": payload.get("action")}
    if what not in ("function_call", "custom_tool_call"):
        return None
    name, space = str(payload.get("name", ""))[:256], str(payload.get("namespace") or "")[:256]
    args = payload.get("arguments", payload.get("input"))
    if what == "function_call" and isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {}
    if name == "apply_patch":
        return "patch", 2, use, {}
    if name in CODEX_SHELLS:
        if isinstance(args, dict):
            return "command", 2, use, {"command": args.get("command", args.get("cmd")),
                                       "cwd": args.get("workdir", args.get("working_directory"))}
        return "command", 2, use, {"command": args if isinstance(args, str) else None}
    if space.startswith("mcp__"):
        return "mcp", 2, use, {"server": space[5:].strip("_"), "tool": name, "args": args}
    if name.startswith("mcp__"):
        server, _, tool = name[5:].partition("__")
        return "mcp", 2, use, {"server": server, "tool": tool, "args": args}
    if what == "custom_tool_call" and name == "exec":
        # Code mode: a script of tool calls, from 0.149 each recorded as a completed item.
        return "code_mode", 2, use, {"script": args if isinstance(args, str) else ""}
    return "tool", 2, use, {"name": name}


def seconds(stamp):
    try:
        return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def replayed(fork, kind, payload, stamp):
    """Whether an entry of a forked rollout is its parent's history, which a fork starts with,
    copied with new times. The fork's own turns have ids made after the fork's; in a log
    without turn ids, its own entries come over a second after the fork."""
    if kind == "turn_context" or kind == "event_msg" and payload.get("type") in ("task_started", "turn_started"):
        started = uuid_ms(payload.get("turn_id"))
        if started is not None:
            fork["turns"] = True
            return fork["id"] is None or started < fork["id"] - 1000
    at = seconds(stamp)
    return fork["turns"] or fork["at"] is None or at is None or at <= fork["at"] + 1


def uuid_ms(value):
    """The time in a UUIDv7, in milliseconds, or None."""
    match = re.match(r"^([0-9a-f]{8})-([0-9a-f]{4})-7", value, re.I) if isinstance(value, str) else None
    return int(match.group(1) + match.group(2), 16) if match else None


# A shell call in a code mode script (`tools.exec_command({cmd: "…"})`), and the command it gives.
CODE_MODE_SHELL = re.compile(r"\btools\.(%s)\s*\(" % "|".join(re.escape(n) for n in sorted(CODEX_SHELLS)))
CODE_MODE_COMMAND = re.compile(r"(?<![\w$])[\"']?(?:cmd|command)[\"']?\s*:\s*"
                               r"(\"(?:[^\"\\\n]|\\.){0,65536}\"|'(?:[^'\\\n]|\\.){0,65536}'"
                               r"|`(?:[^`\\$]|\\.|\$(?!\{)){0,65536}`)")
JS_ESCAPE = re.compile(r"\\(u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\n|.)", re.S)
JS_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0", "\n": ""}


def js_escape(match):
    code = match.group(1)
    if code[0] in "ux" and len(code) > 1:
        return chr(min(int(code.strip("u{}x"), 16), 0x10FFFF))
    return JS_ESCAPES.get(code, code)


def code_mode(events):
    """Code mode's scripts as the shell commands they ran, when the log has no completed item
    for each (Codex 0.144 to 0.148). A script whose commands are built as it runs is counted
    as a tool use and an entry that couldn't be read."""
    items = any(e[0] == "command" and e[1] < 2 for e in events)
    out = []
    for action, rank, use, details, stamp, folder in events:
        if action != "code_mode":
            out.append((action, rank, use, details, stamp, folder))
            continue
        script = details["script"][:COMMAND_MAX]
        if items or not CODE_MODE_SHELL.search(script):
            continue
        commands = [JS_ESCAPE.sub(js_escape, m.group(1)[1:-1]) for m in CODE_MODE_COMMAND.finditer(script)]
        for i, command in enumerate(commands):
            out.append(("command", 2, f"{use}#{i}", {"command": command, "script": codex_script(command)},
                        stamp, folder))
        if not commands:
            ERRORS["calls_skipped"] += 1
            out.append(("tool", 2, use, {"name": "exec"}, stamp, folder))
    return out


def read_codex(home, days, fmt):
    """What one user's Codex rollouts hold within the window, as read_user returns it. A session is one
    Codex thread; a subagent's thread counts as its parent's. Adds the format's counts to `fmt`."""
    since = max(0, time.time() - days * 86400)
    since_iso = datetime.datetime.fromtimestamp(since, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    calls, outputs, mcp, fetches, sessions = [], {}, collections.Counter(), [], set()
    seen, days_active, per = set(), set(), {}
    for path in codex_logs(home):
        opened = open_owned(path, FILE_MAX)
        if not opened:
            continue
        handle, info = opened
        events, aws_calls, answers, at = [], set(), {}, 0
        meta = {"session": "", "own": "", "version": "", "repo": "", "folder": "", "read": False, "fork": None}
        with handle:
            if info.st_mtime < since:
                continue
            try:
                for line in lines_of(handle, CODEX_CALL):
                    at += 1
                    if not line.strip():
                        continue
                    fmt["entries"] += 1
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        entry = None
                    except RecursionError:
                        skip_entry(line, CODEX_CALL)
                        continue
                    try:
                        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str) \
                                or not isinstance(entry.get("payload"), dict):
                            fmt["unparsed_entries"] += 1
                            continue
                        kind, payload, stamp = entry["type"], entry["payload"], str(entry.get("timestamp", ""))[:64]
                        if kind == "session_meta":
                            if not meta["read"]:
                                meta["read"] = True
                                spawned = mapping(mapping(mapping(payload.get("source")).get("subagent"))
                                                  .get("thread_spawn")).get("parent_thread_id")
                                meta["own"] = str(payload.get("id") or "")[:TEXT_MAX]
                                meta["session"] = str(payload.get("parent_thread_id") or spawned
                                                      or payload.get("id") or "")[:TEXT_MAX]
                                meta["version"] = str(payload.get("cli_version", ""))[:64]
                                fmt["versions"][meta["version"]] += 1
                                meta["folder"] = codex_folder(payload.get("cwd"))
                                repo = mapping(payload.get("git")).get("repository_url")
                                meta["repo"] = repo[:TEXT_MAX] if isinstance(repo, str) else ""
                                if payload.get("forked_from_id"):
                                    meta["fork"] = {"id": uuid_ms(payload.get("id")), "at": seconds(stamp),
                                                    "turns": False}
                            continue
                        if meta["fork"] and replayed(meta["fork"], kind, payload, stamp):
                            continue
                        meta["fork"] = None
                        if kind == "turn_context":
                            meta["folder"] = codex_folder(payload.get("cwd")) or meta["folder"]
                            continue
                        use = payload.get("call_id")
                        if payload.get("type") in ("function_call_output", "custom_tool_call_output") \
                                and isinstance(use, str) and use in aws_calls:
                            answers[use] = accounts_in(codex_output(payload.get("output")))
                            continue
                        event = codex_event(kind, payload)
                        if not event or stamp < since_iso:
                            continue
                        action, rank, use, details = event
                        # An entry without an id is keyed by its place in its thread's log, so the
                        # same rollout in sessions/ and archived_sessions/ counts once.
                        use = use[:256] if isinstance(use, str) and use else f"{meta['own'] or path}#{at}"
                        if action == "command":
                            details["script"] = codex_script(details.get("command"))
                            if rank == 2 and details["script"] and AWS_RUN.search(details["script"]):
                                aws_calls.add(use)
                        events.append((action, rank, use, details, stamp, codex_folder(details.get("cwd"))
                                       or meta["folder"]))
                    except Exception:
                        ERRORS["calls_skipped"] += 1
            except OSError:
                ERRORS["files_skipped"] += 1
        session = "codex:" + (meta["session"] or path)
        events = code_mode(events)
        best, first = {}, {}
        for action, rank, use, _, stamp, _ in events:
            best[action] = min(best.get(action, 3), rank)
            first[action, use] = min(first.get((action, use), stamp), stamp)
        chosen = {}
        for event in sorted(events, key=lambda e: e[1]):
            action, rank, use = event[:3]
            # Completed items have ids of their own; web searches often have none.
            if rank == best[action] or (best[action] == 1 and action != "web"):
                chosen.setdefault((action, use), event)
        for (action, use), (_, rank, _, details, _, folder) in sorted(chosen.items(), key=lambda kv: first[kv[0]]):
            stamp = first[action, use]
            if (action, use) in seen:
                continue
            seen.add((action, use))
            sessions.add(session)
            one = per.setdefault(session, {"first": stamp, "last": stamp, "version": meta["version"],
                                           "agent": "codex", "repo": meta["repo"],
                                           "tools": collections.Counter(), "folders": collections.Counter(),
                                           "shell_commands": 0, "mcp_calls": 0, "web_fetches": 0})
            one["first"], one["last"] = min(one["first"], stamp), max(one["last"], stamp)
            if folder:
                one["folders"][folder] += 1
            if re.match(r"^\d{4}-\d\d-\d\d$", stamp[:10]):
                days_active.add(stamp[:10])
            tool = {"command": "shell", "patch": "apply_patch", "mcp": "mcp", "web": "web_search"}.get(action)
            if action == "command" and details["script"] == "":
                tool = "apply_patch"
            elif action == "command" and details["script"]:
                script, at = details["script"], "codex:" + use
                calls.append((stamp, script, folder, at, session))
                one["shell_commands"] += 1
                if AWS_RUN.search(script):
                    outputs[at] = answers.get(use) or accounts_in(codex_output(details.get("output")))
            elif action == "mcp":
                server, name = codex_mcp(details.get("server"), details.get("tool"))
                if server:
                    mcp[(server, name, session, mcp_access(server, name, mapping(details.get("args"))))] += 1
                    one["mcp_calls"] += 1
            elif action == "web":
                step = mapping(details.get("action"))
                if step.get("type") in ("open_page", "openPage") and isinstance(step.get("url"), str):
                    fetches.append(step["url"][:TEXT_MAX])
                    one["web_fetches"] += 1
            elif action == "tool":
                tool = str(details.get("name") or "")[:256] or "unnamed"
            one["tools"][tool] += 1
            fmt["tool_uses"][tool] += 1
    calls.sort()
    return calls, outputs, mcp, sorted(fetches), sessions, [], days_active, per


# --- The facts ---

# What changing an asset puts a session or machine in: a cloud account or
# cluster, named or not, or a registry published to; else a repository
# written or a web host sent data. A prompt sent to an AI API is not a change.
CLOUD_KINDS = ("aws", "azure", "gcp", "kubernetes")
UNNAMED = ("unknown", "default", "current")
AI_APIS = re.compile(r"(^|\.)(api\.openai\.com|api\.anthropic\.com|api\.groq\.com|openrouter\.ai|"
                     r"generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|"
                     r"api\.together\.xyz|api\.deepseek\.com|api\.cohere\.(ai|com)|api\.fireworks\.ai|"
                     r"api\.perplexity\.ai|api\.x\.ai|api\.cerebras\.ai|api\.replicate\.com|"
                     r"openai\.azure\.com|api-inference\.huggingface\.co|router\.huggingface\.co|"
                     r"bedrock-runtime\.[\w-]+\.amazonaws\.com)$")
RISK_GROUPS = ("high", "medium", "none")
CHANGE_GROUPS = ("cloud_or_published", "code_or_data", "read_only")


def change_group(kind, name):
    if kind in CLOUD_KINDS:
        return "cloud_or_published"
    if name in UNNAMED or kind == "web" and AI_APIS.search(name) or kind == "mcp" and LOCAL_MCP.search(name):
        return None
    return {"registries": "cloud_or_published", "repositories": "code_or_data",
            "web": "code_or_data", "mcp": "code_or_data"}.get(kind)


def groups(severities, changes):
    """The group of a session or machine on each dimension: its worst risky
    action and its broadest kind of change."""
    return (next((s for s in RISK_GROUPS[:2] if s in severities), "none"),
            next((g for g in CHANGE_GROUPS[:2] if g in changes), "read_only"))


def by_group(marks, sessions):
    out = {"risky_actions": dict.fromkeys(RISK_GROUPS, 0), "changes": dict.fromkeys(CHANGE_GROUPS, 0)}
    for session in sessions:
        risky, changes = groups(*marks.get(session, ((), ())))
        out["risky_actions"][risky] += 1
        out["changes"][changes] += 1
    return out


class Facts:
    def __init__(self):
        self.findings = {}
        self.resources = {kind: collections.OrderedDict() for kind in KINDS}
        self.other_code = collections.Counter()
        self.other_code_commands = 0
        # Commands that started no other code, by the first kind of system they changed.
        self.visible_changes = collections.Counter()
        self.command_changes = set()
        self.commands = 0
        self.days_active = set()
        self.fetched = []
        self.sessions = []
        self.format = {"claude_code_versions": collections.Counter(), "entries": 0, "unparsed_entries": 0,
                       "tool_uses": collections.Counter()}
        self.start_user("", "")

    def start_user(self, user, home, profiles=None, outputs=None):
        """Read a new user: their name, home, AWS profiles (name -> account)
        and the accounts in their AWS commands' output (tool call -> accounts).
        `session` and `use` are those of what is being read; `marks` has each
        session's events: session -> [severities, change groups]."""
        self.user, self.home, self.profiles, self.outputs = user, home, profiles or {}, outputs or {}
        self.session = self.use = None
        self.stamp = ""
        self.marks = {}
        # session -> {"findings": [...], "shown": Counter, "changes": Counter, "other_code": Counter, ...}
        self.by_session = {}

    def in_session(self):
        return self.by_session.setdefault(self.session, {
            "findings": [], "shown": collections.Counter(), "changes": collections.Counter(),
            "other_code": collections.Counter(), "other_code_commands": 0})

    def rank_fetched(self):
        """Records code run or installed from a URL, its repository counting as
        the user's own when their agents changed it."""
        own = {name for name, e in self.resources["repositories"].items()
               if e["changes"] and self.user in e["users"]}
        for rule, text, at, session, stamp in self.fetched:
            self.session, self.stamp = session, stamp
            tier = source_tier(rule["url"], text, rule["folder"], own)
            self.find(FETCHED[rule["id"]][tier], rule["id"], text, None, at)
        self.fetched = []

    def find(self, rule, what, text, counted=None, at=0):
        """Count a finding; with `counted`, at most once per command."""
        # Some IDs hold a word of the command.
        key = (rule["source"], plain_name(rule["id"], " "))
        if counted is not None:
            if key in counted:
                return
            counted.add(key)
        if "url" in rule:
            # Ranked once the user's repositories are known.
            self.fetched.append((rule, text, at, self.session, self.stamp))
            return
        if key not in self.findings:
            self.findings[key] = {"source": rule["source"], "id": key[1], "tactic": rule["tactic"],
                                  "severity": rule["severity"], "local": bool(rule.get("local")),
                                  "local_only": bool(rule.get("local_only")),
                                  "what": plain_name(what, " "),
                                  "count": 0, "session_count": set(), "users": set(), "examples": []}
        found = self.findings[key]
        found["count"] += 1
        found["users"].add(self.user)
        if self.session:
            found["session_count"].add((self.user, self.session))
        # Candidates for the examples, spread over the logs: the first 8
        # hits, then the 16th, 32nd, 64th…
        if found["count"] <= 8 or found["count"] & (found["count"] - 1) == 0:
            shown = example(text, self.home, at)
            if shown not in found["examples"]:
                found["examples"].append(shown)
        if self.session and not rule.get("local_only"):
            self.marks.setdefault(self.session, [set(), set()])[0].add(rule["severity"])
        if self.session:
            one = self.in_session()
            if len(one["findings"]) < SESSION_FINDINGS_MAX:
                shown = []
                if one["shown"][key] < SESSION_EXAMPLES_MAX:
                    one["shown"][key] += 1
                    shown = [example(text, self.home, at)]
                one["findings"].append({"id": f"{key[0]}:{key[1]}", "at": self.stamp[:TEXT_MAX], "examples": shown})

    def touch(self, kind, name, mode, service=None, tool=None, profiles=None):
        """Count a read, change or call of a resource; for AWS the service and
        the profiles naming the account, for MCP the tool. Every MCP tool call
        is a call, and a read or change when its tool says which."""
        name = safe_name(name, self.home)
        fields = {"ssh": ("calls",), "mcp": ("reads", "changes", "calls"),
                  "repositories": ("reads", "changes", "conversation")}.get(kind, ("reads", "changes"))
        entry = self.resources[kind].setdefault(name, dict(dict.fromkeys(fields, 0), users=set()))
        if "calls" in entry:
            entry["calls"] += 1
        if mode == "conversation":
            entry["conversation"] += 1
        elif mode != "call":
            entry["changes" if mode in ("change", "write", "send") else "reads"] += 1
        entry["users"].add(self.user)
        if mode in ("change", "write", "send") and not (kind == "web" and AI_APIS.search(name)) \
                or kind == "registries":
            self.command_changes.add(kind)
        if self.session and (mode in ("change", "write", "send") or kind == "registries"):
            group = change_group(kind, name)
            if group:
                self.marks.setdefault(self.session, [set(), set()])[1].add(group)
                self.in_session()["changes"][(kind, name)] += 1
        if service is not None:
            entry.setdefault("services", collections.Counter())[safe_name(service, self.home)] += 1
        if profiles is not None:
            entry.setdefault("profiles", set()).update(safe_name(p, self.home) for p in profiles)
        if tool is not None:
            entry.setdefault("tools", collections.Counter())[safe_name(tool, self.home)] += 1


def shell_rule(command):
    """(rule, match) for shellfirm's rule a segment falls under. Some patterns
    are quadratic, so only the first 4 KB is matched."""
    command = command[:4096]
    for rule in SHELL:
        match = rule["pattern"].search(command)
        if match and not any(w in command for w in rule["not_contains"]) \
                and not any(u.search(command) for u in rule["unless"]):
            return rule, match
    return None, None


BOUNDARY = re.compile(r"(;|&&|\|\||\||'|\"|\(|\$\()\s*")


def near(text, start):
    """The text from the start of the command holding position `start`, so a
    long example shows its action."""
    if start <= 50:
        return text
    cut = max((m.end() for m in BOUNDARY.finditer(text, max(0, start - 80), start) if m.end() <= start),
              default=None)
    if cut is None:
        # No command starts near it: start at a word just before it.
        cut = text.rfind(" ", 0, max(0, start - 16)) + 1
    return "…" + text[cut:]


SYSTEM_FOLDERS = {"/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/opt", "/srv", "/System",
                  "/Library", "/Applications", "/private", "/private/etc", "/private/var", "/usr/bin",
                  "/usr/lib", "/usr/local", "/usr/sbin", "/var/lib"}


def wiped(argv, folder, home):
    """"high" if a recursive `rm` deletes a home folder or the disk, "system" for a system
    folder, "medium" for the folder above or a repository's top folder."""
    if not any(a == "--recursive" or re.match(r"^-[a-zA-Z]*[rR]", a) for a in argv[1:]):
        return None
    severity = None
    for target in positional(argv[1:]):
        # `dir/*` counts as the folder.
        bare = "." if target == "*" else target[:-2] or "/" if target.endswith("/*") else target
        bare = bare.rstrip("/") or "/"
        # A relative one, where the folder is known (`cd ~ && rm -rf .`).
        known = folder != "/" and bare.startswith(".")
        full = os.path.normpath(os.path.join(folder, bare)) if known else bare
        if full in ("/", "~", "/root", "/var/root") or os.path.normpath(full) == os.path.normpath(home) \
                or re.match(r"^/(Users|home)/[^/]+$", full):
            return "high"
        if os.path.normpath(full) in SYSTEM_FOLDERS:
            severity = "system"
        if bare == ".." or (bare == "." and inside(folder) and os.path.isdir(os.path.join(folder, ".git"))):
            severity = severity or "medium"
    return severity


VISIBLE_CHANGES = (("code", ("repositories", "registries")), ("cloud", ("aws", "azure", "gcp", "kubernetes")),
                   ("web", ("web",)))


def scan_command(facts, raw, cwd):
    kinds, counted = set(), set()
    facts.command_changes = set()
    scan_text(facts, runnable(raw), cwd, {"HOME": facts.home}, kinds, counted)
    changed = next((name for name, of in VISIBLE_CHANGES if facts.command_changes & set(of)), None)
    if changed and not kinds:
        facts.visible_changes[changed] += 1
    if kinds:
        facts.other_code_commands += 1
        for kind in kinds:
            facts.other_code[kind] += 1
        if facts.session:
            one = facts.in_session()
            one["other_code_commands"] += 1
            one["other_code"].update(kinds)


def asks_help(argv):
    """`--help`, `gh … -h`, `git … -h` or `<tool> help …`: shows usage, changes nothing."""
    args = argv[1:argv.index("--")] if "--" in argv else argv[1:]
    return "--help" in args or args[:1] == ["help"] or (argv[0] in ("gh", "git") and "-h" in args)


DRY_RUN = re.compile(r"(?i)^(--dry-?run(=(?!none$)\S+)?|--what-?if|-whatif|what-if|--noop|--check"
                     r"|--simulate)$")
# Where `-n` means a dry run (`git commit -n` skips hooks instead).
DRY_RUN_N = {"rsync", "make", "git push", "git clean", "git add", "git rm", "git mv"}
PREVIEWS = {"terraform": "plan", "tofu": "plan", "pulumi": "preview", "cdk": "diff", "kubectl": "diff"}


def dry_run(argv):
    """A dry run, plan or preview: shows what would change, changes nothing."""
    args = argv[1:argv.index("--")] if "--" in argv else argv[1:]
    verb = argv[0]
    if verb == "git":
        i = git_verb(argv, "")[0]
        verb, args = "git " + "".join(argv[i:i + 1]), argv[i + 1:]
    return any(DRY_RUN.match(a) for a in args) \
        or PREVIEWS.get(verb) in [a for a in args if a[:1] != "-"][:1] \
        or verb in DRY_RUN_N and any(re.match(r"^-[a-zA-Z]*n[a-zA-Z]*$", a) for a in args)


# Destructive database commands on a database on this machine stay here.
DATABASE_PACKS = ("database", "psql", "mysql", "mongodb", "redis")
LOCAL_DB = re.compile(r"sqlite|\.db(?![\w.-])|\.sqlite3?\b|localhost|127\.0\.0\.1|\[?::1\]?|\.sock\b", re.I)
REMOTE_DB = re.compile(r"(?:-h\s*|--host[=\s]+|://(?:[^@/\s]*@)?)([\w.-]+)")
IN_CONTAINER = re.compile(r"\b(docker|podman)\s+(compose\s+)?exec\b|\bdocker-compose\s+exec\b")
TEST_DB = re.compile(r"(?i)\bdrop\s+database\s+(if\s+exists\s+)?[`'\"]?(\w+_)?tests?(_\w*|\d*)\b")


def local_database(piece):
    """Whether a database command names a database on this machine: a local
    host or file, a container's client, or a test database."""
    host = REMOTE_DB.search(piece)
    if host:
        return local_db_host(host.group(1))
    return bool(LOCAL_DB.search(piece) or IN_CONTAINER.search(piece) or TEST_DB.search(piece))


def local_db_host(host):
    """Whether a database host a command names is on this machine."""
    return bool(local_network(host) or re.search(r"\.(sock|db|sqlite3?)$", host, re.I))


@functools.lru_cache(maxsize=1024)
def segment_rule(piece):
    """(rule, match) for the rule a whole segment falls under."""
    rule, match = shell_rule(piece)
    if not rule:
        rule, match = next(((r, m) for r in OWN_SEGMENT for m in [r["pattern"].search(piece)] if m),
                           (None, None))
    if rule and rule["id"].partition(":")[0] in DATABASE_PACKS and local_database(piece):
        rule = dict(rule, id=rule["id"] + ":local", severity="medium", local=True, local_only=True)
    return rule, match


# A token or password read into a variable or straight into another program, not shown:
# not counted, or at a lower risk.
CAPTURABLE = {"github-token-printed": None, "cloud-token-printed": None,
              "keychain-read": {"source": "own", "id": "keychain-read:captured", "tactic": "Credential Access",
                                "severity": "medium"}}


def captured(piece, program):
    """Whether a segment captures what `program` prints: `$(…)`, piped to `--password-stdin`, discarded."""
    name = re.escape(program)
    return bool(re.search(r"(\$\(|`)\s*(\w+=\S*\s+)*(sudo\s+)?" + name + r"\b"
                          r"|\b" + name + r"\b[^|;&]{0,500}\|[^|;&]{0,500}--password-stdin\b"
                          r"|\b" + name + r"\b[^|;&]{0,500}\s(1|&)?>\s*/dev/null\b", piece))


def scan_text(facts, command, here, env, kinds, counted, depth=0):
    """One command's segments; a shell's `-c` script is read the same way, at
    most 8 deep. At most 200 segments are read."""
    for piece in split_command(command, segments=True)[:200]:
        scripts, start = [], here
        parts, here = command_parts(piece, here, env, scripts)
        # A segment that runs a script is read through the script; one run
        # by ssh leaves the segment's own rules (`tar … | ssh h 'tar x'`).
        piece_found = any(folder is not None for _, folder in scripts)
        # Output piped into a shell runs (`echo <base64> | base64 -d | sh`).
        fed = any(PIPED_INTO.match(os.path.basename(a[0])) and reads_stdin(a) for _, a, _, _ in parts)
        url = piped_run(piece[:4096])
        if url is not None:
            rule = {"source": "own", "id": "download-run", "url": url, "folder": start}
            facts.find(rule, "", piece, counted)
            piece_found = True
        for text, argv, folder, path in parts:
            if asks_help(argv) or dry_run(argv):
                piece_found = True
                continue
            found = scan_part(facts, text, argv, folder, path, fed)
            if found and found[0]["id"] in CAPTURABLE and captured(piece, argv[0]):
                found = CAPTURABLE[found[0]["id"]] and (CAPTURABLE[found[0]["id"]],) + tuple(found[1:])
            if found:
                facts.find(found[0], found[1], text, counted, *found[2:])
                piece_found = True
            kind = hidden_kind(argv, text, path)
            if kind:
                kinds.add(kind)
        if not piece_found:
            # Segment rules are skipped when a part found something, so one
            # action isn't counted twice, and on a read-only pipeline, as
            # written (`echo pw | sudo -S ls` is none).
            rule, match = segment_rule(piece)
            if rule and not all(read_only(split_part(c) or ["?"]) for c in split_command(piece)):
                facts.find(rule, rule["id"], piece, counted, match.start())
        for script, folder in scripts if depth < 8 else []:
            scan_text(facts, uncommented(script), folder or "/", dict(env), kinds, counted, depth + 1)


@functools.lru_cache(maxsize=1024)
def own_rule(text):
    return next((r for r in OWN if r["pattern"].search(text)), None)


# Redirects that write no file.
QUIET_REDIRECT = re.compile(r"^(\d?>>?|&>>?)(/dev/null|&\d)$")


def read_only(argv):
    """Codex's known-safe commands: they can't change anything or run another
    program. They can print a secret file, which secret_read checks."""
    program, args = argv[0], argv[1:]
    unsafe = READ_ONLY["unsafe_options"].get(program, [])
    if program not in READ_ONLY["programs"] or any(
            a in unsafe or a.startswith(tuple(o + "=" for o in unsafe if o.startswith("--"))) for a in args):
        return False
    if program == "base64" and any(a.startswith("-o") for a in args):
        return False
    # sed only as `sed -n 5p` or `sed -n 1,5p`.
    if program == "sed" and not (len(args) in (2, 3) and args[0] == "-n"
                                 and re.match(r"^\d+(,\d+)?p$", args[1])):
        return False
    # A redirect writes a file (`echo k >> ~/.ssh/authorized_keys`).
    return not any((">" in a or a.startswith("<(")) and not QUIET_REDIRECT.match(a) for a in args)


def sigma_rule(path, argv):
    """The Sigma rule a part falls under, matched as Sigma sees a process:
    its image (a bare name as found on the PATH) and its command line."""
    image = path if "/" in path else "/usr/bin/" + path
    # A process's command line holds no redirects; the shell did them.
    args = [a for i, a in enumerate(argv[1:])
            if not REDIRECT.match(a) and not (i and REDIRECT_ALONE.match(argv[i]))]
    subject = (image + "\t" + " ".join([path] + args))[:4096]
    low = subject.lower()
    rules = sigma_rules(os.path.basename(image).lower(), SIGMA_SCREEN.search(low) is not None)
    return next((r for r in rules if (not r["keys"] or any(k in low for k in r["keys"]))
                 and r["pattern"].match(subject)), None)


@functools.lru_cache(maxsize=512)
def sigma_rules(name, any_key):
    """The rules for a program, high first; those for any program only when
    the command holds a word one of them needs."""
    rules = SIGMA_BY_IMAGE.get(name, []) + (SIGMA_ANY if any_key else [])
    return sorted(rules, key=lambda r: r["severity"] != "high")


def scan_part(facts, text, argv, folder, path=None, fed=False):
    """Records the resources one part reached; returns its finding as
    (rule, what[, at])."""
    program, profiles = argv[0], facts.profiles
    found = None

    if program == "aws":
        call = aws_call(argv)
        if call:
            service, op, method, profile = call
            profile = profile or "default"
            accounts = {profiles[profile]} if profile in profiles else set()
            accounts |= accounts_in(text)
            if not accounts:
                accounts = set(facts.outputs.get(facts.use, ()))
            mode = aws_access(method, op)
            for account in sorted(accounts) or ["unknown"]:
                facts.touch("aws", account, mode, service=service,
                            profiles={p for p, a in profiles.items() if a == account})
            flags = AWS["flags"].get(method or "")
            if method == "SecretsManager.DeleteSecret" and "--force-delete-without-recovery" in argv:
                found = (SECRET_PURGED, method)
            elif flags and not (method in SSM_READS and "--with-decryption" not in argv):
                found = (flags[0], method)
            elif mode == "change" and method and VERB_IMPACT.match(method.split(".", 1)[1]):
                found = ({"source": "aws-api-name", "id": method, "tactic": "Impact", "severity": "medium"},
                         method)
    elif program == "gh":
        touched = gh_touch(argv, folder)
        if touched:
            facts.touch("repositories", touched[0], touched[1])
        rule = next((r for r in GITHUB if r["pattern"].search(text)), None)
        if rule and rule["action"] == "repo.access" and argv[1:3] == ["repo", "create"]:
            # `gh repo create --public` makes nothing private public.
            rule = PUBLIC_REPO
        if rule:
            found = (rule, rule["action"])
    elif program == "git":
        touched = git_touch(argv, folder)
        if touched:
            facts.touch("repositories", touched[0], touched[1])
        rule = force_push(argv, folder) or remote_deletion(argv, folder)
        if rule:
            found = (rule, rule["id"])
    elif program == "az":
        verb = cloud_verb(argv, AZ_SKIP)
        if verb:
            facts.touch("azure", named(option(argv, "--subscription"), "default"), cloud_mode(verb, argv))
    elif program == "gcloud":
        verb = cloud_verb(argv, GCLOUD_SKIP)
        if verb:
            facts.touch("gcp", named(option(argv, "--project"), "default"), cloud_mode(verb, argv))
    elif program in ("kubectl", "oc"):
        rest = positional(argv[1:], KUBE_VALUED)
        if rest and rest[0] not in KUBE_SKIP:
            reads = rest[0] in KUBE_READ or rest[:1] == ["rollout"] and rest[1:2] in (["status"], ["history"])
            facts.touch("kubernetes", named(option(argv, "--context"), "current"), "read" if reads else "change")
    elif program in ("curl", "wget"):
        for host, mode in web_touch(argv):
            facts.touch("web", host, mode)
        host = upload(argv)
        # A whole file sent anywhere, or any upload to an anonymous file-drop site, is how files
        # leave; a form upload to an API (a speed test, an attachment) is a change to that host.
        whole = re.search(r"(^|\s)(-T|--upload-file|--post-file)([ =]|$)", text)
        if host and (whole or DROP_SITES.search(host)):
            sent = whole or re.search(r"\S*@\S+", text)
            found = ({"source": "own", "id": "file-uploaded", "tactic": "Exfiltration",
                      "severity": "high" if DROP_SITES.search(host) else "medium"}, "file upload to " + host,
                     sent.start() if sent else 0)
    elif program in ("ssh", "scp", "rsync", "sftp"):
        # A session is reach, not a change: the remote host logs what it did.
        for host in ssh_hosts(argv):
            facts.touch("ssh", host, "call")
    elif program == "rm":
        severity = wiped(argv, folder, facts.home)
        if severity:
            found = (WIPED[severity], WIPED[severity]["id"])

    registry = registry_of(argv)
    if registry:
        facts.touch("registries", registry, "change")

    if not found:
        # Input redirected from a file reads it (`nc host 9000 < ~/.ssh/id_rsa`).
        taken = [b for a, b in zip(argv, argv[1:]) if re.match(r"^\d*<$", a)] \
            + [a.split("<", 1)[1] for a in argv[1:] if re.match(r"^\d*<[^<(&]", a)]
        secret = secret_read(argv, facts.home, folder) if program in READERS else None
        secret = secret or (secret_read(["cat"] + taken, facts.home, folder) if taken else None)
        if secret:
            found = secret_rule(*secret, facts.home)

    if found:
        return found
    # Sigma's broad rules skip a read-only command, unless a shell runs its output.
    rule = own_rule(text) or (fed or not read_only(argv)) and sigma_rule(path or program, argv)
    if rule:
        found = (rule, rule["id"])
    if not found:
        package = PACKAGE_URL.search(text)
        if package:
            url = next(g for g in reversed(package.groups()) if g)
            found = ({"source": "own", "id": "package-from-url", "url": url, "folder": folder}, "",
                     package.start())
    return found


def collect_user(facts, home, days, number=1):
    user = f"user-{number}"
    _REMOTES.clear()
    profiles = aws_profiles(home)
    calls, outputs, mcp, fetches, sessions, reads, days_active, per = read_user(home, days, facts.format)
    codex = {"versions": collections.Counter(), "entries": 0, "unparsed_entries": 0,
             "tool_uses": collections.Counter()}
    more = read_codex(home, days, codex)
    if codex["entries"]:
        old = facts.format.setdefault("codex", codex)
        if old is not codex:
            for key in codex:
                old[key] += codex[key]
    calls = sorted(calls + more[0])
    outputs.update(more[1])
    mcp.update(more[2])
    fetches = sorted(fetches + more[3])
    sessions |= more[4]
    days_active |= more[6]
    per.update(more[7])
    facts.start_user(user, home, profiles, outputs)
    facts.days_active |= days_active
    by_agent = collections.Counter(per.get(s, {}).get("agent", "claude-code") for s in sessions)
    stats = {"name": user, "sessions": len(sessions), "shell_commands": len(calls),
             "mcp_calls": sum(mcp.values()), "web_fetches": len(fetches)}
    if by_agent["codex"]:
        stats["sessions_by_agent"] = dict(sorted(by_agent.items()))

    for stamp, raw, cwd, use, session in calls:
        facts.commands += 1
        facts.session, facts.use, facts.stamp = session, use, stamp
        try:
            scan_command(facts, raw, cwd)
        except Exception:
            ERRORS["calls_skipped"] += 1

    facts.rank_fetched()
    for path, session, stamp in reads:
        secret = secret_file(path, home)
        if secret:
            rule, what = secret_rule(secret, path, home)
            facts.session, facts.stamp = session, stamp
            facts.find(rule, what, "Read " + path)
    for (server, tool, session, mode), n in sorted(mcp.items()):
        facts.session = session
        for _ in range(n):
            facts.touch("mcp", server, mode, tool=tool)
    facts.session, facts.stamp = None, ""
    stats["sessions_by_group"] = by_group(facts.marks, sessions)
    facts.sessions += session_records(facts, per, home)
    for host in filter(None, map(web_host, fetches)):
        facts.touch("web", host, "read")
    return stats


def session_id(session):
    """A session's id in the output: never the agent's session id itself."""
    return "s_" + hashlib.sha256(SESSION_SALT + session.encode("utf-8", "replace")).hexdigest()[:12]


def session_project(folders, home, recorded=""):
    """The repository a session mostly worked in, as `owner/repo`; else the remote the agent
    recorded for it (Codex does), else `local project`. Never a path."""
    for folder, _ in folders.most_common():
        remotes = remotes_of(folder) if inside(folder) else {}
        repo = remotes.get("origin") or next(iter(sorted(remotes.values())), None)
        if repo:
            return safe_name(repo, home)
    repo = repo_name(recorded) if recorded else None
    return safe_name(repo, home) if repo else "local project"


def session_records(facts, per, home):
    """One record per session with a medium- or high-risk action or a change.
    No user, prompt, output, path or environment."""
    out = []
    for session, (severities, changes) in sorted(facts.marks.items()):
        if not ({"high", "medium"} & severities or changes) or session not in per:
            continue
        span, one = per[session], facts.by_session.get(session) or {}
        agent = {"agent": "codex", "codex_version": span["version"]} if span.get("agent") == "codex" \
            else {"claude_code_version": span["version"]}
        out.append({
            "id": session_id(session),
            "started": span["first"], "ended": span["last"],
            **agent,
            "project": session_project(span["folders"], home, span.get("repo", "")),
            "counts": {"shell_commands": span["shell_commands"], "mcp_calls": span["mcp_calls"],
                       "web_fetches": span["web_fetches"], "tool_uses": dict(sorted(span["tools"].items()))},
            "findings": sorted(one.get("findings", []), key=lambda f: f["at"]),
            "changes": [{"kind": k, "name": n, "count": c}
                        for (k, n), c in sorted(one.get("changes", {}).items(), key=lambda kv: (-kv[1], kv[0]))],
            "other_code": {"commands": one.get("other_code_commands", 0),
                           "by_kind": dict(sorted(one.get("other_code", {}).items()))},
        })
    return out


def plain(value):
    """Sets and counters as sorted lists and dicts."""
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, collections.Counter):
        return dict(sorted(value.items()))
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    return value


def fail(message, code=2):
    print(message, file=sys.stderr)
    sys.exit(code)


def has_logs(home):
    return any(os.path.isdir(os.path.join(home, *p)) for p in (
        (".claude", "projects"), (".codex", "sessions"), (".codex", "archived_sessions")))


def homes_to_read(given):
    """(home, uid, gid) for each home to read. As root, every real account whose
    home it owns and holds ~/.claude/projects or ~/.codex/sessions; HOME,
    CLAUDE_CONFIG_DIR and CODEX_HOME are not used."""
    import pwd  # not on Windows, where main() stops first

    if given:
        out = []
        for home in given:
            home = os.path.abspath(home)
            try:
                info = os.stat(home)
            except OSError:
                fail(f"{home} doesn't exist.")
            if not has_logs(home):
                ERRORS["homes_skipped"] += 1
                print(f"{home} has no .claude/projects or .codex/sessions; no session logs read there.",
                      file=sys.stderr)
            out.append((home, info.st_uid, info.st_gid))
        return out
    if os.geteuid() != 0:
        # A uid with no account (a container's `-u 1000`) still has a HOME.
        try:
            return [(pwd.getpwuid(os.getuid()).pw_dir, os.getuid(), os.getgid())]
        except KeyError:
            return [(os.path.expanduser("~"), os.getuid(), os.getgid())]
    first = 500 if platform.system() == "Darwin" else 1000
    found, seen = [], set()
    for account in sorted(pwd.getpwall(), key=lambda a: (a.pw_dir, a.pw_uid)):
        home, uid = os.path.abspath(account.pw_dir or "/"), account.pw_uid
        if (uid == 0 and home not in ("/var/root", "/root")) or (uid != 0 and not first <= uid < 65534) \
                or home in seen:
            continue
        try:
            info = os.stat(home)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and info.st_uid == uid and has_logs(home):
            seen.add(home)
            found.append((home, uid, account.pw_gid))
    return found


def checked_out(path):
    """The output path; exits 2 if it is a link or its folder is writable by others."""
    path = os.path.abspath(path)
    folder = os.path.dirname(path)
    if os.path.islink(path):
        fail(f"{path} is a link; the file isn't written through links.")
    try:
        writable = os.stat(folder).st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    except OSError as error:
        fail(f"Can't write to {folder}: {error.strerror}.")
    if writable:
        fail(f"{folder} can be written by other users; choose a folder only its owner can write to.")
    return path


def write_out(path, text):
    """Write the file whole or not at all, mode 0600."""
    path = checked_out(path)
    folder = os.path.dirname(path)
    temp = os.path.join(folder, f".{os.path.basename(path)}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp)
        raise


# Placeholders some vendors leave in the serial number field.
NO_SERIAL = re.compile(r"(?i)^(0*|none|n/?a|default string|not specified|system serial number"
                       r"|to be filled by o\.e\.m\.)$")


def hardware():
    """(serial number, hash of the hardware id). The hash tells apart machines
    with the same name."""
    serial = raw = ""
    if sys.platform == "darwin":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            out = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=10).stdout
            raw = (re.search(r'"IOPlatformUUID" = "([^"]+)"', out) or [None, ""])[1]
            serial = (re.search(r'"IOPlatformSerialNumber" = "([^"]+)"', out) or [None, ""])[1]
    else:
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            with contextlib.suppress(OSError):
                raw = pathlib.Path(path).read_text()[:64].strip()
                break
        # Readable by root only on most distributions.
        with contextlib.suppress(OSError):
            serial = pathlib.Path("/sys/class/dmi/id/product_serial").read_text()[:64].strip()
    return serial, hashlib.sha256(raw.encode()).hexdigest()[:16] if raw else ""


def default_name(serial, hashed, hostname):
    """The serial number, which the MDM lists; host names often hold the owner's name, so never one."""
    if serial and not NO_SERIAL.match(serial):
        return serial
    return hashed[:12] or host_hash(hostname)[2:14]


def host_hash(hostname):
    """Stable across runs, so a machine collected twice is still recognised, without its name."""
    return "h_" + hashlib.sha256(f"agent-activity-host:{hostname.lower()}".encode()).hexdigest()[:16]


FILES_FOLDER = "agent-activity-files"


def default_folder(root, system, home):
    """A folder only root can read when an MDM runs it, else agent-activity-files
    next to this file, where `report` looks when given no folder."""
    if root:
        return "/Library/Application Support/AgentActivity" if system == "Darwin" \
            else "/var/lib/agent-activity"
    return os.path.join(HERE, FILES_FOLDER)


def make_own_folder(folder):
    """Create the user's files folder; False when it can't be used safely."""
    try:
        with contextlib.suppress(FileExistsError):
            os.mkdir(folder, 0o700)
        info = os.lstat(folder)
        return stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
    except OSError:
        return False


def make_root_folder(folder):
    try:
        with contextlib.suppress(FileExistsError):
            os.mkdir(folder, 0o700)
        info = os.lstat(folder)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            fail(f"{folder} must be a folder owned by root.")
        os.chmod(folder, 0o700)  # nosemgrep: insecure-file-permissions (owner-only)
    except OSError as error:
        fail(f"Can't create {folder}: {error.strerror}.")


def upload_request(url, name, body):
    """The PUT that sends the file to an upload link; `{name}` in the link
    becomes the machine's name. Raises ValueError for a link that isn't HTTPS."""
    url = url.strip().replace("{name}", urllib.parse.quote(name, safe=""))
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("The upload link must start with https://.")
    headers = {"Content-Type": "application/json"}
    if parts.hostname.endswith(".blob.core.windows.net"):
        headers["x-ms-blob-type"] = "BlockBlob"
    return urllib.request.Request(url, data=body, headers=headers, method="PUT")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could send the file to a host the link didn't name."""

    def redirect_request(self, *args):
        return None


def send(request):
    """None, or why the upload failed."""
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
            response.read(4096)
    except urllib.error.HTTPError as error:
        return f"the server answered {error.code} {error.reason}"
    except (urllib.error.URLError, OSError) as error:
        return str(getattr(error, "reason", error))
    return None


def arguments(argv, upload_url):
    """(options, upload link). Jamf runs a script as `script / <computer> <user>
    <parameter 4> …`; parameter 4 is the upload link."""
    if argv[:1] == ["/"]:
        upload_url = (argv[3] if len(argv) > 3 else "") or upload_url
        argv = []
    parser = argparse.ArgumentParser(
        description="Collect what coding agents did on this machine into one file. "
                    "To build the report from the collected files: report [FOLDER] [--org NAME].")
    parser.add_argument("--days", type=int, default=30, help="how many days of logs to read (default 30)")
    parser.add_argument("--out", help="the file to write, or - for standard output")
    parser.add_argument("--home", action="append",
                        help="a home folder to read (repeatable); default is every user")
    parser.add_argument("--name",
                        help="the name the report uses for this machine; default is its serial number")
    parser.add_argument("--upload",
                        help="an HTTPS link to send the file to (a PUT; {name} becomes the machine's name)")
    args = parser.parse_args(argv)
    if args.days <= 0:
        parser.error("--days must be 1 or more")
    return args, (args.upload or upload_url).strip()


def main(argv=None, upload_url=""):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["report"]:
        import report
        return report.main(argv[1:])
    if sys.platform == "win32":
        fail("This tool runs on macOS and Linux; Windows isn't supported.", 1)
    args, upload_url = arguments(argv, upload_url)
    root = os.geteuid() == 0
    serial, hashed = hardware()
    name = plain_name(args.name or default_name(serial, hashed, socket.gethostname()))
    if upload_url:
        try:
            upload_request(upload_url, name, b"")
        except ValueError as error:
            fail(str(error))
        if args.out == "-":
            fail("An upload needs a file; leave out --out -.")
    out = fallback = None
    if args.out and args.out != "-":
        out = checked_out(args.out)
    elif not args.out:
        home = os.path.expanduser("~")
        folder = default_folder(root, platform.system(), home)
        if root:
            make_root_folder(folder)
        elif not make_own_folder(folder):
            folder = home
        base = "agent-activity-%s.json" % re.sub(r"[^\w.-]", "_", name)[:64]
        out = checked_out(os.path.join(folder, base))
        # Falls back to the home when the folder isn't writable (or macOS blocks it).
        fallback = os.path.join(home, base) if folder != home and not root else None

    facts, users = Facts(), []
    for home, uid, gid in homes_to_read(args.home):
        OWNER.update(given=home, home=os.path.realpath(home), uid=uid)
        try:
            with as_user(uid, gid):
                users.append(collect_user(facts, home, args.days, len(users) + 1))
        except Exception as error:
            ERRORS["homes_skipped"] += 1
            print(f"Couldn't read {home}: {error}.", file=sys.stderr)
    findings = sorted(facts.findings.values(), key=lambda f: (SEVERITY_RANK[f["severity"]], f["tactic"],
                                                              -f["count"], f["source"], f["id"]))
    resources = {}
    for kind, entries in facts.resources.items():
        ordered = sorted(entries.items(), key=lambda kv: (kv[0] == "unknown", -kv[1].get("changes", 0),
                                                          -kv[1].get("calls", kv[1].get("reads", 0)), kv[0]))
        resources[kind] = [dict(plain(e), name=name) for name, e in ordered]
    out_data = {
        "schema": SCHEMA,
        "collector": {"version": VERSION, "rules": rule_files()},
        "endpoint": {"hostname": host_hash(socket.gethostname()),
                     "name": name,
                     "machine_id": hashed,
                     "os": f"{platform.system()} {platform.release()}",
                     "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "days": args.days,
                     "first_activity": min(facts.days_active, default=""),
                     "last_activity": max(facts.days_active, default="")},
        "users": [plain(u) for u in users],
        "totals": {"shell_commands": facts.commands, "findings": sum(f["count"] for f in findings),
                   "mcp_calls": sum(u["mcp_calls"] for u in users),
                   "web_fetches": sum(u["web_fetches"] for u in users)},
        "findings": [dict(plain(f), session_count=len(f["session_count"]), examples=distinct(f["examples"]))
                     for f in findings],
        "resources": resources,
        "executed_other_code": {"commands": facts.other_code_commands, "of": facts.commands,
                                "by_kind": dict(sorted(facts.other_code.items())),
                                "visible_changes": {name: facts.visible_changes[name] for name, _ in VISIBLE_CHANGES}},
        "format": plain(facts.format),
        "errors": dict(ERRORS),
        "sessions": sorted(facts.sessions, key=lambda r: (r["started"], r["id"]))[-SESSIONS_MAX:],
    }
    text = json.dumps(out_data, indent=1, ensure_ascii=False) + "\n"
    if out is None:
        print(text, end="")
        return 0
    for out in filter(None, (out, fallback)):
        try:
            write_out(out, text)
            break
        except OSError as error:
            why = f"Couldn't write {out}: {error.strerror}."
    else:
        fail(why)
    who = "1 user" if len(users) == 1 else f"{len(users)} users"
    read = [a for a, n in (("Claude Code", facts.format["entries"]),
                           ("Codex", facts.format.get("codex", {}).get("entries"))) if n]
    if read:
        print(f"Read the {' and '.join(read)} logs of {who}: {facts.commands:,} agent commands "
              f"in the last {args.days} days.")
    else:
        print(f"Found no Claude Code or Codex logs from the last {args.days} days on this machine; "
              "the file says so.")
    print(f"Saved {out}", flush=True)
    if upload_url:
        request = upload_request(upload_url, name, text.encode("utf-8"))
        why = send(request)
        if why:
            print(f"The upload failed ({why}); the file is still at {out}.", file=sys.stderr)
            return 1
        print(f"Uploaded to {urllib.parse.urlsplit(request.full_url).hostname}.")
    elif not root:
        print("Send this file to your security team.")
        if sys.platform == "darwin" and sys.stdout.isatty():
            subprocess.run(["/usr/bin/open", "-R", out], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
