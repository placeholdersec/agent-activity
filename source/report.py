#!/usr/bin/env python3
"""Merge the collector's endpoint files into one organisation report.

Endpoint files are untrusted: any local user controls the logs they come from.
Malformed files are skipped, and every string is stripped of control characters
and cut to length before it reaches the page, the facts or the digest.

People are counted, never named: in the facts, developers are opaque IDs.

Usage: agent-activity.py report [FOLDER] [--out report.html] [--org NAME]
"""

import argparse
import base64
import collections
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import unicodedata
from html import escape

from collect import (AI_APIS, CHANGE_GROUPS, DATABASE_PACKS, ERRORS, FILES_FOLDER, HERE, KINDS, KNOWN,
                     LOCAL_DB, LOCAL_MCP, REMOTE_DB, RISK_GROUPS, SCHEMA, SEVERITY_RANK, SIGMA, UNNAMED,
                     change_group, distinct, groups, local_db_host, shipped, under, utf8_output)

TACTICS = {"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Collection", "Command and Control", "Exfiltration", "Impact"}
OTHER_CODE_NAMES = {"inline_code": "inline code", "scripts": "scripts", "containers": "containers",
                    "task_runners": "task runners", "builds_tests": "builds and tests",
                    "deploy_tools": "deploy tools"}
LEARN_MORE = "https://www.placeholdersec.com/assessment/learn-more"
OTHER_CODE_WHAT = {
    "inline_code": ("Code typed straight into the command", ("python -c", "node -e")),
    "scripts": ("A script file", ("python deploy.py", "./run.sh")),
    "containers": ("Whatever runs inside the container", ("docker run", "docker exec", "docker compose up")),
    "task_runners": ("Whatever the target or script runs", ("make", "npm run", "npx")),
    "builds_tests": ("The project's own code, run by its build or tests", ("pytest", "cargo test", "go test")),
    "deploy_tools": ("Whatever the tool works out to deploy", ("terraform apply", "pulumi up", "cdk deploy")),
}
# In the order a sentence names them.
OTHER_CODE_STARTED = (("scripts", "a script"), ("inline_code", "inline code"), ("task_runners", "a build"),
                      ("builds_tests", "a build"), ("deploy_tools", "a deploy tool"),
                      ("containers", "a container"))
# Logs with none of these tools, or many unparsed entries, are an unknown format, not a quiet endpoint.
KNOWN_TOOLS = {"Bash", "PowerShell", "Monitor", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep",
               "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite", "NotebookEdit", "mcp"}
AGENTS = (("claude-code", "Claude Code"), ("codex", "Codex"))
AGENT_NAMES = dict(AGENTS)
# Commands that started no other code, by the first kind of system they changed.
VISIBLE = ("code", "cloud", "web")
UNPARSED_SHARE = 0.1
MAX_BYTES = 50 * 1024 * 1024
NAME_CAP, EXAMPLE_CAP = 128, 160
DIGEST_MACHINES = 40
MAX_DEPTH = 32


def clean(text, cap=NAME_CAP):
    """Strip control, format and other non-printing characters; cut to `cap`."""
    text = "".join(c if c == " " or unicodedata.category(c)[0] not in "CZ" else " " for c in text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= cap else text[:cap - 1] + "…"


class TooDeep(Exception):
    pass


def scrub(value):
    """clean() every string, keys included; TooDeep when nested deeper than MAX_DEPTH."""
    def leaf(v, key):
        if isinstance(v, str):
            return clean(v, EXAMPLE_CAP if key in ("example", "examples") else NAME_CAP)
        return {} if isinstance(v, dict) else [] if isinstance(v, list) else v
    out = leaf(value, None)
    todo = [(value, out, None, 1)] if isinstance(value, (dict, list)) else []
    while todo:
        src, dst, key, depth = todo.pop()
        if depth > MAX_DEPTH:
            raise TooDeep()
        for k, v in (src.items() if isinstance(src, dict) else ((key, v) for v in src)):
            child = leaf(v, k)
            if isinstance(src, dict):
                dst[clean(k)] = child
            else:
                dst.append(child)
            if isinstance(v, (dict, list)):
                todo.append((v, child, k, depth + 1))
    return out


def count(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def counts(d):
    return isinstance(d, dict) and all(isinstance(k, str) and count(v) for k, v in d.items())


def strings(x):
    return isinstance(x, list) and all(isinstance(v, str) for v in x)


def is_str(x):
    return isinstance(x, str)


def is_bool(x):
    return isinstance(x, bool)


def has(d, test, *keys):
    """Whether `d` is a dict whose `keys` are all there and pass `test`."""
    return isinstance(d, dict) and all(k in d and test(d[k]) for k in keys)


COUNTED = dict({kind: ("reads", "changes") for kind in KINDS}, ssh=("calls",),
               mcp=("reads", "changes", "calls"))
EXTRAS = {"aws": (("services", counts), ("profiles", strings)), "mcp": (("tools", counts),)}


def problem(data):
    """Why `data` isn't a well-formed endpoint file, or None."""
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return "not an endpoint file"
    if not has(data.get("collector"), is_str, "version"):
        return "bad collector block"
    end = data.get("endpoint")
    if not (has(end, is_str, "hostname", "name", "machine_id", "collected_at", "first_activity",
                "last_activity") and end["hostname"] and end["name"] and has(end, count, "days")):
        return "bad endpoint block"
    users = data.get("users")
    if not (isinstance(users, list)
            and all(has(u, is_str, "name") and has(u, count, "sessions")
                    and isinstance(u.get("sessions_by_group"), dict)
                    and all(has(u["sessions_by_group"].get(d), count, *gs) for d, gs in GROUPS.items())
                    and counts(u.get("sessions_by_agent", {}))
                    and set(u.get("sessions_by_agent", {})) <= set(AGENT_NAMES)
                    and sum(u.get("sessions_by_agent", {}).values()) in (0, u["sessions"])
                    for u in users)):
        return "bad users"
    if not (counts(data.get("totals")) and "shell_commands" in data["totals"]):
        return "bad totals"
    if not isinstance(data.get("findings"), list):
        return "bad findings"
    for f in data["findings"]:
        if not (has(f, is_str, "source", "id", "what", "severity", "tactic") and f["severity"] in SEVERITY_RANK
                and f["tactic"] in TACTICS and has(f, count, "count")
                and has(f, strings, "users", "examples") and f["examples"]
                and has(f, is_bool, "local", "local_only")
                and ("session_count" not in f or count(f["session_count"]) and f["session_count"] <= f["count"])):
            return "bad finding"
    res = data.get("resources")
    if not isinstance(res, dict):
        return "bad resources"
    for kind in KINDS:
        if not (isinstance(res.get(kind), list)
                and all(has(r, is_str, "name") and has(r, strings, "users") and has(r, count, *COUNTED[kind])
                        and all(has(r, test, key) for key, test in EXTRAS.get(kind, ()))
                        and (kind != "repositories" or "conversation" not in r or count(r["conversation"]))
                        for r in res[kind])):
            return f"bad {kind} resource"
    run = data.get("executed_other_code")
    if not (has(run, count, "commands", "of") and run["commands"] <= run["of"] and counts(run.get("by_kind"))
            and ("visible_changes" not in run
                 or counts(run["visible_changes"]) and has(run["visible_changes"], count, *VISIBLE)
                 and run["commands"] + sum(run["visible_changes"][k] for k in VISIBLE) <= run["of"])):
        return "bad executed_other_code"
    fmt = data.get("format")
    if not (has(fmt, count, "entries", "unparsed_entries")
            and has(fmt, counts, "claude_code_versions", "tool_uses")
            and ("codex" not in fmt or has(fmt["codex"], count, "entries", "unparsed_entries")
                 and has(fmt["codex"], counts, "versions", "tool_uses"))):
        return "bad format"
    if not (counts(data.get("errors")) and has(data["errors"], count, *ERRORS)):
        return "bad errors"
    return None


SESSION_ID = re.compile(r"^s_[0-9a-f]{12}$")
SESSION_COUNTS = ("shell_commands", "mcp_calls", "web_fetches")


def session_record(r):
    """The record checked field by field, or None; a bad record drops alone, not its file."""
    try:
        codex = isinstance(r, dict) and r.get("agent") == "codex"
        ok = (isinstance(r, dict) and is_str(r.get("id")) and SESSION_ID.match(r["id"])
              and has(r, is_str, "started", "ended", "codex_version" if codex else "claude_code_version", "project")
              and has(r.get("counts"), count, *SESSION_COUNTS) and counts(r["counts"].get("tool_uses"))
              and isinstance(r.get("findings"), list)
              and all(has(x, is_str, "id", "at") and has(x, strings, "examples") for x in r["findings"])
              and isinstance(r.get("changes"), list)
              and all(has(x, is_str, "kind", "name") and x["kind"] in KINDS and has(x, count, "count")
                      for x in r["changes"])
              and has(r.get("other_code"), count, "commands") and counts(r["other_code"].get("by_kind")))
    except (TypeError, KeyError, AttributeError):
        ok = False
    if not ok:
        return None
    agent = {"agent": "codex", "codex_version": r["codex_version"]} if codex \
        else {"claude_code_version": r["claude_code_version"]}
    return {"id": r["id"], "started": r["started"], "ended": r["ended"], **agent, "project": r["project"],
            "counts": {**{k: r["counts"][k] for k in SESSION_COUNTS}, "tool_uses": dict(r["counts"]["tool_uses"])},
            "findings": [{"id": x["id"], "at": x["at"], "examples": list(x["examples"][:3])} for x in r["findings"][:200]],
            "changes": [{"kind": x["kind"], "name": x["name"], "count": x["count"]} for x in r["changes"]],
            "other_code": {"commands": r["other_code"]["commands"], "by_kind": dict(r["other_code"]["by_kind"])}}


def load(folder):
    """(files, skipped, dropped): one (name, data) per endpoint, skipped with why, superseded files."""
    files, skipped = [], []
    for path in sorted(pathlib.Path(folder).glob("*.json")):
        if path.name.endswith(".facts.json"):  # a report's own facts
            continue
        name = clean(path.name)
        try:
            if path.is_symlink() or not path.is_file():
                skipped.append((name, "not a regular file"))
                continue
            if path.stat().st_size > MAX_BYTES:
                skipped.append((name, "larger than 50 MB"))
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            skipped.append((name, "not readable JSON"))
            continue
        # Scrubbed before checking, so a name of only control characters is no name.
        try:
            data = scrub(data)
            why = problem(data)
        except TooDeep:
            why = "nested too deep"
        except Exception:  # an unforeseen shape skips its file, not the report
            why = "not a well-formed endpoint file"
        if why:
            skipped.append((name, why))
        else:
            files.append((name, data))
    # Latest file per machine (id, host name and the name it was given): a machine collected again, as root
    # or as one user, counts once; homes collected under names of their own (--name) count apart.
    latest, dropped = {}, []
    for name, data in sorted(files, key=lambda nf: (nf[1]["endpoint"]["collected_at"], nf[0])):
        key = (machine(data), data["endpoint"]["hostname"], data["endpoint"]["name"])
        if key in latest:
            dropped.append((latest[key][0], f"older file from {data['endpoint']['name']}, kept {name}"))
        latest[key] = (name, data)
    kept = [data for _, data in sorted(latest.values(), key=lambda nf: nf[0])]
    # Duplicate names get a machine-id prefix, the whole id, or the host name; never who used the machine.
    taken = collections.Counter(d["endpoint"]["name"] for d in kept)
    short = collections.Counter((d["endpoint"]["name"], machine(d)[:8]) for d in kept)
    full = collections.Counter((d["endpoint"]["name"], machine(d)) for d in kept)
    for d in kept:
        end, key = d["endpoint"], machine(d)
        if taken[end["name"]] > 1:
            tag = key[:8] if short[end["name"], key[:8]] == 1 else key
            if full[end["name"], key] > 1:
                tag = end["hostname"]
            end["name"] = f"{end['name']} ({tag})"
    # Names still alike, such as a machine already called "box (host)", take an ordinal.
    seen = collections.Counter()
    for d in kept:
        end = d["endpoint"]
        seen[end["name"]] += 1
        if seen[end["name"]] > 1:
            end["name"] = f"{end['name']} #{seen[end['name']]}"
    return kept, skipped, dropped


def assessable(f):
    """Whether an endpoint's agents ran a command, called an MCP tool, fetched a page or read a secret."""
    return bool(f["totals"]["shell_commands"] or f["totals"]["mcp_calls"] or f["totals"]["web_fetches"]
                or f["findings"])


def machine(data):
    """A machine's id; its host name when the collector couldn't read one."""
    return data["endpoint"]["machine_id"] or data["endpoint"]["hostname"]


def merge(files):
    endpoints = sorted({f["endpoint"]["name"] for f in files})
    users = sorted({(f["endpoint"]["name"], u["name"]) for f in files for u in f["users"]})
    totals = collections.Counter()
    for f in files:
        totals.update(f["totals"])

    # A rule counts once per session it matched in: the file's own count, else its session records holding it.
    findings, per_session = {}, True
    for f in sorted(files, key=lambda f: f["endpoint"]["name"]):
        host = f["endpoint"]["name"]
        own = [session_record(r) for r in (f.get("sessions") if isinstance(f.get("sessions"), list) else [])]
        own = [r for r in own if r]
        held = collections.Counter(i for r in own for i in {x["id"] for x in r["findings"]})
        for x in f["findings"]:
            key = (x["source"], x["id"])
            m = findings.setdefault(key, {"source": x["source"], "id": x["id"], "tactic": x["tactic"],
                                          "severity": x["severity"], "local": x["local"],
                                          "local_only": x["local_only"], "what": x["what"], "count": 0,
                                          "session_count": 0, "endpoints": collections.Counter(),
                                          "users": set(), "examples": []})
            if "session_count" in x:
                in_sessions = x["session_count"]
            elif own:
                in_sessions = min(x["count"], max(held[f"{key[0]}:{key[1]}"], 1))
            else:
                in_sessions, per_session = x["count"], False
            m["examples"] += x["examples"]
            m["count"] += x["count"]
            m["session_count"] += in_sessions
            m["endpoints"][host] += x["count"]
            m["users"].update((host, u) for u in x["users"])

    for m in findings.values():
        m["examples"] = distinct(m["examples"])
    resources = {kind: {} for kind in KINDS}
    for f in sorted(files, key=lambda f: f["endpoint"]["name"]):
        host = f["endpoint"]["name"]
        for kind in KINDS:
            for x in f["resources"][kind]:
                m = resources[kind].setdefault(x["name"], {
                    "name": x["name"], "reads": 0, "changes": 0, "calls": 0,
                    "endpoints": collections.Counter(), "users": set(), "services": collections.Counter(),
                    "tools": collections.Counter(), "profiles": set()})
                if kind == "repositories":
                    m.setdefault("conversation", 0)
                    m["conversation"] += x.get("conversation", 0)
                for field in COUNTED[kind]:
                    m[field] += x[field]
                m["endpoints"][host] += x["calls"] if "calls" in x else x["reads"] + x["changes"] + x.get("conversation", 0)
                m["users"].update((host, u) for u in x["users"])
                m["services"].update(x.get("services", {}))
                m["tools"].update(x.get("tools", {}))
                m["profiles"].update(x.get("profiles", []))

    other_code, visible = collections.Counter(), collections.Counter()
    other_code_commands = commands = 0
    for f in files:
        other_code_commands += f["executed_other_code"]["commands"]
        commands += f["executed_other_code"]["of"]
        other_code.update(f["executed_other_code"]["by_kind"])
        visible.update({k: f["executed_other_code"].get("visible_changes", {}).get(k, 0) for k in VISIBLE})
    # Older files don't say which commands changed what; then no command is put on a branch.
    visible = dict(visible) if all("visible_changes" in f["executed_other_code"] for f in files) else None
    sessions = sum(u["sessions"] for f in files for u in f["users"])
    # Session records carry their machine, never who ran them.
    records = []
    for f in sorted(files, key=lambda f: f["endpoint"]["name"]):
        for r in f.get("sessions") if isinstance(f.get("sessions"), list) else []:
            kept = session_record(r)
            if kept:
                records.append(dict(kept, machine=f["endpoint"]["name"]))
    records.sort(key=lambda r: (r["started"], r["machine"], r["id"]))
    for key, m in findings.items():
        name = f"{key[0]}:{key[1]}"
        m["sessions"] = sorted({r["id"] for r in records if any(x["id"] == name for x in r["findings"])})

    fmt = {"claude_code_versions": collections.Counter(), "entries": 0, "unparsed_entries": 0,
           "tool_uses": collections.Counter()}
    errors = collections.Counter()
    unread_format = []
    for f in files:
        errors.update(f["errors"])
        entries, tools = f["format"]["entries"], f["format"]["tool_uses"]
        codex = f["format"].get("codex")
        if entries and (not any(tools.get(t) for t in KNOWN_TOOLS)
                        or f["format"]["unparsed_entries"] > UNPARSED_SHARE * entries) \
                or codex and codex["unparsed_entries"] > UNPARSED_SHARE * codex["entries"]:
            unread_format.append(f["endpoint"]["name"])
        for key in ("entries", "unparsed_entries"):
            fmt[key] += f["format"][key]
        for key in ("claude_code_versions", "tool_uses"):
            fmt[key].update(f["format"][key])
        if codex:
            into = fmt.setdefault("codex", {"versions": collections.Counter(), "entries": 0,
                                            "unparsed_entries": 0, "tool_uses": collections.Counter()})
            for key in into:
                into[key] += collections.Counter(codex[key]) if isinstance(into[key], collections.Counter) \
                    else codex[key]
    agents = collections.Counter()
    for f in files:
        for u in f["users"]:
            agents.update(u.get("sessions_by_agent") or {"claude-code": u["sessions"]})

    dated = [(f["endpoint"]["first_activity"], f["endpoint"]["last_activity"]) for f in files]
    dated = [d for d in dated if all(iso_day(x) for x in d)]
    span = (min(a for a, _ in dated), max(b for _, b in dated)) if dated else None
    return {
        "endpoints": endpoints, "users": users, "totals": totals, "findings": findings,
        "resources": resources, "other_code": other_code, "other_code_commands": other_code_commands,
        "commands": commands, "visible_changes": visible, "sessions": sessions, "session_records": records,
        "per_session": per_session,
        "days": sorted({f["endpoint"]["days"] for f in files}), "span": span,
        "collected": sorted(f["endpoint"]["collected_at"] for f in files),
        "format": fmt, "errors": errors, "unread_format": sorted(unread_format),
        "agents": {a: agents[a] for a, _ in AGENTS if agents[a]},
        "per_endpoint": {f["endpoint"]["name"]: endpoint_groups(f) for f in files},
    }


CHANGED_KINDS = (("aws", "AWS account", "AWS accounts"), ("repositories", "repository", "repositories"),
                 ("web", "web host", "web hosts"), ("registries", "registry", "registries"),
                 ("azure", "Azure subscription", "Azure subscriptions"),
                 ("gcp", "Google Cloud project", "Google Cloud projects"),
                 ("kubernetes", "Kubernetes cluster", "Kubernetes clusters"),
                 ("mcp", "SaaS tool via MCP", "SaaS tools via MCP"))
UNNAMED_AS = {"aws": ("unknown", "Account not identifiable"), "azure": ("default", "Subscription not named"),
              "gcp": ("default", "Project not named"), "kubernetes": ("current", "Context not named")}


def unnamed(kind, x):
    """Whether `x` is the cloud asset of its kind the logs don't name."""
    return kind in UNNAMED_AS and x["name"] in UNNAMED


def changed(r, kind):
    """Named assets an agent changed; a registry counts once published to, AI API prompts and local MCP don't."""
    return [x for x in r[kind].values() if x["name"] not in UNNAMED and (x["changes"] or kind == "registries")
            and not (kind == "web" and AI_APIS.search(x["name"])) and not (kind == "mcp" and local_mcp(x))]


def local_mcp(x):
    return bool(LOCAL_MCP.search(x["name"]))


# One group per dimension for each machine and session: its worst risky action, its broadest change.
GROUPS = {"risky_actions": RISK_GROUPS, "changes": CHANGE_GROUPS}
GROUP_NAMES = {"high": "High-risk", "medium": "Medium-risk", "none": "None",
               "cloud_or_published": "Cloud & packages", "code_or_data": "Code & data",
               "read_only": "No changes"}


def session_groups(users):
    return {d: {g: sum(u["sessions_by_group"][d][g] for u in users) for g in gs} for d, gs in GROUPS.items()}


def endpoint_groups(f):
    """An endpoint's own counts and its group per dimension, from all its events."""
    r = {kind: {x["name"]: x for x in f["resources"][kind]} for kind in KINDS}
    changes = {change_group(kind, x["name"]) for kind, _, _ in CHANGED_KINDS for x in r[kind].values()
               if x["changes"] or kind == "registries"}
    risky, changes = groups({x["severity"] for x in f["findings"] if not x["local_only"]}, changes)
    return {"commands": f["executed_other_code"]["of"],
            "changed": sum(len(changed(r, kind)) for kind, _, _ in CHANGED_KINDS),
            "sessions": session_groups(f["users"]), "risky_actions": risky, "changes": changes}


def iso_day(text):
    try:
        return re.match(r"^\d{4}-\d\d-\d\d$", text) and datetime.date.fromisoformat(text)
    except ValueError:
        return None


def most_first(counter):
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def top(counter, n):
    return ", ".join(k for k, _ in most_first(counter)[:n]) or "—"


def first(items, n=8):
    """The items a long list shows before "Show all": all of them when only a few more."""
    return items if len(items) <= n + 2 else items[:n]


def noun(n, one, many=None):
    return one if n == 1 else many or one + "s"


def plural(n, one, many=None):
    return f"{n:,} {noun(n, one, many)}"


def joined(items, last="and"):
    """"a, b and c"; each item once."""
    items = list(dict.fromkeys(items))
    return ", ".join(items[:-1]) + f" {last} " + items[-1] if len(items) > 1 else "".join(items)


# Labels name the attempt, not an outcome: whether a command succeeded isn't collected.
GITHUB_WORDS = {
    "repo.destroy": "Repository deleted", "repo.access": "Repository made public",
    "repo.archived": "Repository archived", "protected_branch.destroy": "Branch protection removed",
    "repo.add_member": "Repository collaborator added", "org.add_member": "Organisation member added",
    "org.update_member": "Organisation owner or admin added",
    "public_key.create": "Deploy or SSH key added", "hook.create": "Webhook added",
    "repository_secret_scanning_push_protection.disable": "Secret-scanning push protection turned off",
}
OWN_WORDS = {
    "force-push:default-branch": "Force push to the default or a release branch",
    "force-push:default-branch-with-lease": "Force push to the default or a release branch (with lease)",
    "force-push:branch": "Force push to a branch",
    "force-push:branch-with-lease": "Force push to a branch, with lease",
    "force-push:unnamed": "Force push, branch not named",
    "force-push:unnamed-with-lease": "Force push with lease, branch not named",
    "remote-branch-deleted": "Remote branch deleted",
    "remote-default-branch-or-tag-deleted": "Default, release or protected branch, or tag, deleted on the remote",
    "keychain-read:captured": "Keychain or credential store secret read into a variable",
    "cloud-token-printed": "Cloud access token printed", "reverse-shell": "Reverse shell opened",
    "disk-overwritten": "Disk overwritten or formatted", "system-folder-deleted": "System folder deleted",
    "secret-deleted-for-good": "Secret deleted without recovery",
    "local-branch-deleted": "Local branch deleted",
    "package-published": "Package published", "github-token-printed": "GitHub token read (gh auth token)",
    "infrastructure-destroyed": "Infrastructure destroyed", "database-migrated": "Database migration pushed",
    "database-reset": "Database reset", "function-deployed": "Function deployed",
    "platform-secret-set": "Platform secret set", "keychain-read": "Keychain or credential store secret read",
    "credential-names-listed": "Saved credential names listed",
    "cloud-metadata-credentials": "Cloud metadata credentials read", "secret-value-read": "Secret value read",
    "file-uploaded": "File uploaded",
    "download-run:known-pinned": "Known installer run (pinned)",
    "download-run:known-unpinned": "Known installer run (unpinned)",
    "download-run:unknown": "Script from an unknown source run",
    "package-from-url:known-pinned": "Package from a known repository (pinned)",
    "package-from-url:known-unpinned": "Package from a known repository (unpinned)",
    "package-from-url:unknown": "Package from an unknown source",
    "archive-piped-out": "Archive piped to a remote host", "dns-exfiltration": "DNS exfiltration",
    "local-history-discarded": "Local history discarded", "hooks-bypassed": "Git hooks skipped",
    "scheduled-job": "Scheduled job, service or autostart added", "public-repo-created": "Public repository created",
    "home-or-root-deleted": "Home folder or disk deleted", "project-deleted": "Project folder deleted",
    "ssh-key-authorized": "SSH key authorized", "environment-printed": "Environment variables printed",
    "sudo-password-in-command": "Password piped to sudo",
    "branch-protection-bypassed": "Pull request merged past branch protection (--admin)",
    "ci-secret-deleted": "GitHub secret deleted (gh secret remove)",
    "agent-guardrails-off": "Coding agent run without guardrails",
    "system-shutdown": "Machine shut down or restarted",
    "shell-startup-changed": "Shell startup file changed",
    "login-or-sudo-config-changed": "Sign-in, sudo or preload configuration changed",
    "kernel-module-loaded": "Kernel module loaded", "setuid-set": "Setuid bit or capability set",
    "root-certificate-trusted": "Root certificate trusted",
    "gatekeeper-bypassed": "Downloaded-file check bypassed",
    "tunnel-opened": "Tunnel opened to this machine", "packet-capture": "Network traffic captured",
    "browser-credentials-read": "Browser cookies or saved logins read",
    "python-startup-hook": "Python startup hook added", "remote-desktop-enabled": "Remote access turned on",
    "defender-weakened": "Microsoft Defender exclusion added or protection turned off",
    "firewall-turned-off": "Firewall turned off", "execution-policy-loosened": "PowerShell script policy loosened",
    "local-account-created": "Local user account created", "administrator-added": "Administrator rights granted",
}


SECRET_WORDS = {"personal-credentials": "Personal credentials read",
                "project-secrets": "Project secrets read", "shell-history": "Shell history read",
                "agent-settings": "Coding agent settings read"}
PACK_NAMES = {"github": "GitHub", "aws": "AWS", "gcp": "Google Cloud", "npm": "npm", "flyio": "Fly.io",
              "mongodb": "MongoDB", "mysql": "MySQL", "psql": "PostgreSQL"}


SHELLFIRM_WORDS = {
    "database:drop_database": "Database dropped", "database:drop_table": "Database table dropped",
    "database:drop_schema_role_user": "Database schema, role or user dropped",
    "database:truncate_table": "Database table emptied (TRUNCATE)",
    "database:update_all_rows": "Every row of a table updated", "psql:drop": "PostgreSQL object dropped",
    "git:push_delete_branch": "Remote branch deleted (git push --delete)",
    "git:push_mirror": "Mirror push, overwriting the remote",
    "github:release_delete": "GitHub release deleted", "github:repo_archive": "GitHub repository archived",
    "github:repo_delete": "GitHub repository deleted", "github:repo_rename": "GitHub repository renamed",
    "github:secret_delete": "GitHub secret deleted", "github:variable_delete": "GitHub variable deleted",
    "gcp:delete_instance": "Google Cloud instance deleted",
    "gcp:delete_service_account": "Google Cloud service account deleted",
    "kubernetes:delete_all_resources": "All Kubernetes resources deleted",
    "redis:flushall": "Redis data wiped (FLUSHALL)",
    "terraform:apply_with_auto_approve": "Terraform apply without review (-auto-approve)",
    "terraform:destroy_auto_approve": "Terraform destroy without review (-auto-approve)",
    "terraform:state_rm": "Terraform state entry removed",
    "vercel:env_remove": "Vercel environment variable removed",
}


def sigma_title(title):
    """Sentence case, without Sigma's 'PUA - ' prefix or a platform suffix."""
    title = re.sub(r"^PUA - |\s+-\s+(Linux|MacOS|macOS|Unix)$", "", title)
    words = title.split()
    return " ".join([words[0]] + [w.lower() if re.fullmatch(r"[A-Z][a-z]+", w) else w for w in words[1:]])


def spaced(camel):
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|\b)|[A-Z]?[a-z]+|\d+", camel)
    return " ".join(w if w.isupper() and len(w) > 1 else w.lower() for w in words).capitalize()


def label(f):
    source, ident, what = f["source"], f["id"], f["what"]
    if source == "sigma":
        rule = SIGMA["rules"].get(ident, {})
        return label(dict(f, source="", what=what)) if "." in what else sigma_title(rule.get("title", ident))
    if source == "own":
        return OWN_WORDS.get(ident, ident)
    if source == "claude-code-safety-net":
        kind, _, name = ident.partition(":")
        return SECRET_WORDS.get(kind, "Credentials file access") + f" ({name})"
    if source == "panther" and what in GITHUB_WORDS:
        return GITHUB_WORDS[what]
    if "." in what and what.split(".", 1)[0][:1].isupper():
        service, method = what.split(".", 1)
        return f"AWS {service}: {spaced(method).lower()}"
    if source == "shellfirm":
        base, local = re.subn(r":local$", "", ident)
        pack, _, rest = base.partition(":")
        generic = f"{PACK_NAMES.get(pack, pack.capitalize())}: " + rest.replace("_", " ")
        name = SHELLFIRM_WORDS.get(base, generic)
        return name + " (local database)" * local
    return what


# Within a risk level, actions an egress control can see (they reach other systems) sort first.
COVERAGE_RANK = {"covered": 0, "partly": 1, "local": 2}


def is_database(f):
    return f["id"].partition(":")[0] in DATABASE_PACKS if f["source"] == "shellfirm" else \
        f["source"] == "own" and f["id"] in ("database-migrated", "database-reset")


def coverage(f):
    """"covered", "partly" or "local": whether an egress control sees the action.
    A secret read is seen once sent; a database command only if the example shows a remote host."""
    if f["local"]:
        return "local"
    if f["id"] in ("keychain-read", "keychain-read:captured", "github-token-printed", "cloud-token-printed") \
            or f["source"] == "claude-code-safety-net":
        return "partly"
    if is_database(f):
        host = REMOTE_DB.search(f["examples"][0])
        if host and not local_db_host(host.group(1)):
            return "covered"
        if LOCAL_DB.search(f["examples"][0]):
            return "local"
        if f["source"] == "shellfirm":
            # A platform command (supabase db push) is remote; a client (psql, redis-cli) may be local.
            return "partly"
    return "covered"


PART = re.compile(r"<!--part:(\w+)-->\n?(.*?)\n?<!--/part:\1-->\n?", re.S)
WHEN = re.compile(r"<!--if:(\w+)-->\n?(.*?)<!--/if:\1-->\n?", re.S)
SLOT = re.compile(r"\{\{\{(\w+)\}\}\}|\{\{(\w+)\}\}")

WELL_KNOWN = json.loads(shipped("rules/well_known_hosts.json"))["hosts"]


def site(host):
    """The domain a host is under, near enough: example.co.uk for a.b.example.co.uk."""
    labels = host.split(".")
    if not re.search(r"[a-z]", labels[-1]):
        return host
    return ".".join(labels[-3 if len(labels) > 2 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else -2:])


def squash(text):
    return re.sub(r"[^a-z0-9]", "", text.lower())


def familiar(r):
    """The org's own domains as far as the data shows: reached from several machines, a repo host, a written repo's owner."""
    on, own = collections.defaultdict(set), set()
    for x in r["web"].values():
        if not under(x["name"].lower(), KNOWN["unknown_hosts"]):
            on[site(x["name"].lower())].update(x["endpoints"])
    for name, x in r["repositories"].items():
        parts = name.lower().split("/")
        if len(parts) == 3:
            own.add(squash(site(parts[0])))
        if x["changes"] and len(parts) > 1:
            own.add(squash(parts[-2]))
    return own | {squash(s) for s, ends in on.items() if len(ends) > 1}


def rare(x, n_end, own):
    """Sent to from one of several machines, not well-known or the org's; a host anyone can publish to never is."""
    host = x["name"].lower()
    if n_end < 2 or not x["changes"] or len(x["endpoints"]) != 1:
        return False
    return under(host, KNOWN["unknown_hosts"]) or not (
        AI_APIS.search(host) or under(host, WELL_KNOWN)
        or {squash(site(host)), squash(site(host).split(".")[0])} & own)


def fill(text, values):
    """{{name}} escaped, {{{name}}} raw markup, <!--if:name--> blocks kept when true.
    One pass, so a value is never read as a slot."""
    while WHEN.search(text):
        text = WHEN.sub(lambda m: m.group(2) if values.get(m.group(1)) else "", text)

    def one(match):
        raw, plain = match.group(1), match.group(2)
        if raw:
            return str(values.get(raw, ""))
        return escape(str(values.get(plain, "")))
    return SLOT.sub(one, text)


FONTS = (("space-grotesk-latin.woff2", "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,"
          "U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD"),
         ("space-grotesk-latin-ext.woff2", "U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,"
          "U+1E00-1E9F,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF"))


def font_css():
    faces = []
    for name, ranges in FONTS:
        data = base64.b64encode(shipped("assets/" + name)).decode()
        faces.append('@font-face{font-family:"Space Grotesk";font-style:normal;font-weight:300 700;'
                     f'font-display:swap;src:url(data:font/woff2;base64,{data}) format("woff2");'
                     f'unicode-range:{ranges}}}')
    return "\n".join(faces)


def logo_svg():
    svg = shipped("assets/wordmark.svg").decode("utf-8")
    return re.sub(r"^<\?xml[^>]*>\s*", "", svg).replace("<svg ", '<svg role="img" aria-label="logo" ', 1)


def names(endpoints, cap=10):
    items = sorted(endpoints, key=lambda n: (n.lower(), n))
    return ", ".join(items[:cap]) + (f" and {len(items) - cap:,} more" if len(items) > cap else "")


def dimensions(m, by_severity, n_changed, n_actions):
    """The two cards' counts, and the machines and sessions in each group."""
    per = m["per_endpoint"].values()
    dims = {}
    for key, title in (("risky_actions", "Risky actions"), ("changes", "Non-read actions on assets")):
        machines = {g: sum(x[key] == g for x in per) for g in GROUPS[key]}
        sessions = {g: sum(x["sessions"][key][g] for x in per) for g in GROUPS[key]}
        if key == "risky_actions":
            severity = next((s for s in ("high", "medium") if by_severity[s]["times"]), None)
            n, hit = (by_severity[severity]["sessions"], (severity,)) if severity else (0, ())
        else:
            severity, n, hit = None, n_changed, GROUPS[key][:2]
        top = GROUPS[key][0]
        dims[key] = {"title": title, "severity": severity, "count": n, "low": by_severity["low"]["times"],
                     "actions": n_actions if key == "changes" else None,
                     "per_session": m["per_session"] if key == "risky_actions" else None,
                     "machines": sum(machines[g] for g in hit),
                     "sessions_with": sum(sessions[g] for g in hit),
                     "top_group": GROUP_NAMES[top], "machines_top": machines[top],
                     "sessions_top": sessions[top],
                     "machines_any": sum(machines[g] for g in GROUPS[key][:2]),
                     "sessions_any": sum(sessions[g] for g in GROUPS[key][:2]),
                     "machine_groups": {GROUP_NAMES[g]: c for g, c in machines.items()},
                     "session_groups": {GROUP_NAMES[g]: c for g, c in sessions.items()}}
    return dims


def by_kind(r):
    """(changed, read) per asset kind; changes in unnamed accounts count, AI API prompts don't."""
    changes, reads = [], []
    for kind, one, many in CHANGED_KINDS + (("ai", "AI API", "AI APIs"),):
        xs = [x for x in r["web" if kind == "ai" else kind].values()
              if (kind not in ("web", "ai") or (kind == "ai") == bool(AI_APIS.search(x["name"])))
              and not (kind == "mcp" and local_mcp(x))]
        n_changes = sum(x["changes"] for x in xs)
        if n_changes and kind != "ai":
            changes.append({"kind": kind, "one": one, "many": many, "n": len(changed(r, kind)),
                            "unnamed": sum(x["changes"] > 0 and unnamed(kind, x) for x in xs),
                            "changes": n_changes})
        read = [x for x in xs if x["reads"]]
        if read:
            n_unnamed = sum(unnamed(kind, x) for x in read)
            reads.append({"kind": kind, "one": one, "many": many, "n": len(read) - n_unnamed,
                          "unnamed": n_unnamed, "reads": sum(x["reads"] for x in read)})
    return changes, reads


def read_problems(m):
    """(what couldn't be read, the very large entries passed over), as sentences."""
    errors = m["errors"]
    unread = joined([plural(errors[k], one, many) for k, one, many in (
        ("homes_skipped", "home folder", None), ("files_skipped", "log file", None),
        ("calls_skipped", "log entry with commands", "log entries with commands")) if errors[k]])
    said = [f"{unread} couldn't be read."] if unread else []
    if m["unread_format"]:
        whose = plural(len(m["unread_format"]), "machine's", "machines'")
        said.append(f"{whose} logs weren't in a format the collector reads.")
    large = errors["large_entries_skipped"]
    passed = (f"{plural(large, 'very large log entry', 'very large log entries')}, such as pasted images, "
              f"{noun(large, 'was', 'were')} skipped. No commands were missed.")
    return " ".join(said), passed if large else ""


def report(m, org):
    """Everything the page says, as plain values; the facts carry it too, so answers never recompute."""
    n_end, r = len(m["endpoints"]), m["resources"]
    findings = sorted(m["findings"].values(), key=lambda f: (
        SEVERITY_RANK[f["severity"]], COVERAGE_RANK[coverage(f)], -len(f["users"]), -f["count"], f["tactic"],
        f["id"]))
    for f in findings:
        f["label"], f["coverage"] = label(f), coverage(f)
    # Local-only findings are listed apart and set no group.
    local = [f for f in findings if f["local_only"]]
    findings = [f for f in findings if not f["local_only"]]
    by_severity = {}
    for s in SEVERITY_RANK:
        hits = [f for f in findings if f["severity"] == s]
        by_severity[s] = {"times": sum(f["count"] for f in hits), "sessions": sum(f["session_count"] for f in hits),
                          "machines": len(set().union(*(f["endpoints"] for f in hits)))}
    changed_by_kind, read_by_kind = by_kind(r)
    dims = dimensions(m, by_severity, sum(k["n"] for k in changed_by_kind),
                      sum(k["changes"] for k in changed_by_kind))
    card_lines = {key: lines(d, n_end) for key, d in dims.items()}
    for key, d in dims.items():
        d["says"] = {k: untag(v) for k, v in card_lines[key].items()}
    started = joined([words for kind, words in OTHER_CODE_STARTED if m["other_code"].get(kind)], "or")
    unread, large = read_problems(m)
    span = f"activity from {m['span'][0]} to {m['span'][1]}" if m["span"] else \
        "last " + "/".join(str(d) for d in m["days"]) + " days"
    own = familiar(r)
    return {
        "org": org, "made": max(m["collected"])[:10], "dimensions": dims, "card_lines": card_lines,
        "span": span,
        "local_mcp": sorted(x for x in r["mcp"] if LOCAL_MCP.search(x)),
        "ai_apis": sum(1 for x in r["web"] if AI_APIS.search(x)),
        "endpoints": n_end, "developers": len(m["users"]), "by_severity": by_severity,
        "gap_heading": f"{plural(m['other_code_commands'], 'command')} executed "
                       f"{started or 'a script, inline code or a container'}"
                       if m["other_code_commands"] else "Every command shows what it did",
        "changed_by_kind": changed_by_kind, "read_by_kind": read_by_kind,
        "rare": sorted(x["name"] for x in r["web"].values() if rare(x, n_end, own)),
        "changed_assets": {k["many"]: k["n"] for k in changed_by_kind if k["n"]},
        "other_code_share": round(m["other_code_commands"] / m["commands"], 4) if m["commands"] else 0,
        "findings": findings, "shown": first(findings), "local": local, "unread": unread, "large": large,
        "idle": f"{plural(len(m['idle']), 'machine')} had no agent activity to assess (no command, MCP tool "
                "call or web fetch in their logs) and aren't counted." if m["idle"] else "",
    }


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def day(iso):
    y, mo, d = iso.split("-")
    return f"{int(d)} {MONTHS[int(mo) - 1]} {y}"


def untag(markup):
    return re.sub(r"<[^>]+>", "", markup)


ONCE_PER_SESSION = ", counted once per session"


def lines(d, n_end):
    """A card's headline and spread, as markup."""
    if d["actions"] is None:
        headline = f"<b>{d['count']:,}</b> {noun(d['count'], (d['severity'] or 'high') + '-risk action')}" \
            + ONCE_PER_SESSION * bool(d["per_session"]) \
            if d["count"] else "No high- or medium-risk action" if d["low"] else "No risky action"
    elif d["actions"]:
        headline = f"<b>{d['actions']:,}</b> {noun(d['actions'], 'non-read action')}" \
            + (f" on {plural(d['count'], 'asset')}" if d["count"] else "")
    else:
        headline = "No non-read action"
    total = sum(d["session_groups"].values())
    spread = []
    if d["machines"]:
        spread.append(f"on <b>{d['machines']:,} of {n_end:,}</b> {noun(n_end, 'machine')}")
    if total and d["sessions_with"]:
        spread.append(f"in <b>{d['sessions_with']:,} of {total:,}</b> {noun(total, 'session')}")
    return {"headline": headline, "spread": " · ".join(spread)}


TACTIC_PLAIN = {"Impact": ("trash", "Deleted or overwrote things"),
                "Credential Access": ("key", "Read passwords, keys and tokens"),
                "Exfiltration": ("globe", "Sent code or data out"),
                "Execution": ("down", "Ran code from unverified sources"),
                "Privilege Escalation": ("alert", "Gave itself more access"),
                "Persistence": ("history", "Left users, jobs or secrets behind"),
                "Defense Evasion": ("eyeoff", "Skipped safety checks"),
                "Initial Access": ("lock", "Opened access to others"),
                "Discovery": ("search", "Looked around"), "Collection": ("search", "Gathered data"),
                "Lateral Movement": ("server", "Reached other machines"),
                "Command and Control": ("server", "Talked to a remote controller"),
                "Reconnaissance": ("search", "Looked around"), "Resource Development": ("package", "Prepared resources")}
# kind: (icon, name, category)
SYSTEM = {"aws": ("cloud", "AWS", "Cloud"), "gcp": ("cloud", "Google Cloud", "Cloud"),
          "azure": ("cloud", "Azure", "Cloud"), "kubernetes": ("hex", "Kubernetes", "Compute"),
          "ssh": ("server", "SSH hosts", "Compute"), "repositories": ("branch", "Code repositories", "Code"),
          "registries": ("package", "Package registries", "Code"), "web": ("globe", "Websites and APIs", "Online services"),
          "mcp": ("plug", "SaaS tools via MCP", "Online services")}
SYSTEM_ONE = {"aws": "AWS account", "gcp": "Google Cloud project", "azure": "Azure subscription",
              "kubernetes": "Kubernetes cluster", "ssh": "SSH host", "repositories": "Code repository",
              "registries": "Package registry", "web": "Website or API", "mcp": "SaaS tool via MCP"}
CATEGORIES = (("Cloud", "cloud"), ("Compute", "hex"), ("Code", "branch"), ("Online services", "globe"))
SEV_WORD = {"high": "High", "medium": "Medium", "low": "Low"}


def icon(name):
    return f'<svg class="i" aria-hidden="true"><use href="#i-{name}"/></svg>'


def ficon(name, x, y, size=24, cls="ac"):
    """An icon inside a flow picture."""
    return (f'<svg class="fi {cls}" x="{x:.1f}" y="{y:.1f}" width="{size}" height="{size}" viewBox="0 0 24 24" '
            f'aria-hidden="true"><use href="#i-{name}"/></svg>')


def opens(i):
    """What makes an element open side panel `i`."""
    return f' data-dw="{escape(i)}" tabindex="0" role="button"'


def panel(panels, i, title, sub, inner):
    panels[i] = (title, sub, inner)
    return opens(i)


def link(xa, ya, xb, yb, w, cls):
    xm = (xa + xb) / 2
    return (f'<path d="M{xa:.1f},{ya:.1f} C{xm:.1f},{ya:.1f} {xm:.1f},{yb:.1f} {xb:.1f},{yb:.1f}" '
            f'class="{cls}" stroke-width="{w:.1f}"/>')


def chips_of(names_, cap=6):
    items = sorted(names_, key=lambda n: (n.lower(), n))
    more = f'<span class="chip more">+{len(items) - cap:,} more</span>' if len(items) > cap else ""
    return '<div class="chips">' + "".join(f'<span class="chip">{escape(n)}</span>' for n in items[:cap]) + more + "</div>"


def system_name(kind, x):
    return f'<span class="unn">{escape(UNNAMED_AS[kind][1])}</span>' if unnamed(kind, x) else f"<code>{escape(x['name'])}</code>"


def counts_change(kind, x):
    """Whether `x`'s changes count as changes: not a prompt to an AI API, not a tool on the machine."""
    return x["changes"] and not (kind == "web" and AI_APIS.search(x["name"])) and not (kind == "mcp" and local_mcp(x))


def changes_by_kind(m):
    """kind -> [(system, changes)], most first, for every kind with a change."""
    out = {}
    for kind in KINDS:
        xs = sorted((x for x in m["resources"][kind].values() if counts_change(kind, x)),
                    key=lambda x: (-x["changes"], unnamed(kind, x), x["name"]))
        if xs:
            out[kind] = xs
    return out


def head_and_figures(m, rep):
    n_changes = sum(x["changes"] for xs in changes_by_kind(m).values() for x in xs)
    sev = rep["by_severity"]
    n_risky = sev["high"]["sessions"] + sev["medium"]["sessions"]
    pencil = '<svg class="i chg" aria-hidden="true"><use href="#i-pencil"/></svg>'
    alert = '<svg class="i rsk" aria-hidden="true"><use href="#i-alert"/></svg>'
    return (f'<section class="panel heads"><h2>Your agents acted on your systems, and some of what they ran was risky.</h2>'
            f'<a class="head" href="#risky">{alert}<b>{n_risky:,}</b><span class="t">{noun(n_risky, "risky action")} agents ran or tried</span></a>'
            f'<a class="head" href="#systems">{pencil}<b>{n_changes:,}</b><span class="t">{noun(n_changes, "write operation")} agents ran on your systems</span></a></section>')


def tactic_counts(rep):
    """(tactic, counts) for every tactic with a high or medium action, busiest first."""
    out = {}
    for f in rep["findings"]:
        d = out.setdefault(f["tactic"], {"high": 0, "medium": 0, "low": 0, "on": set(), "findings": []})
        d[f["severity"]] += f["session_count"]
        d["findings"].append(f)
        if f["severity"] != "low":
            d["on"] |= set(f["endpoints"])
    return sorted(((t, d) for t, d in out.items() if d["high"] or d["medium"]),
                  key=lambda td: (-td[1]["high"], -td[1]["medium"], td[0]))


def session_link(key, name, ids, system=False):
    if not ids:
        return '<span class="muted">–</span>'
    return (f'<span class="dwlink" data-dw="sessions" data-arg="{escape(key)}"{" data-sys" * system} '
            f'data-label="{escape(name)}" tabindex="0" role="button">{len(ids):,} ›</span>')


# Set by html_report: the files have no session records (older collector), unlike --no-sessions.
OLD_FILES = [False]


def finding_card(f, sessions_by_finding):
    """An action in a panel: its sessions when the files have them, else up to three examples."""
    key = f"{f['source']}:{f['id']}"
    on = sorted(f["endpoints"], key=lambda n: (n.lower(), n))
    ids = sessions_by_finding.get(key, [])
    if ids:
        detail = (f'<span class="dwlink" data-dw="sessions" data-arg="{escape(key)}" data-label="{escape(f["label"])}" '
                  f'tabindex="0" role="button">See {plural(len(ids), "session")} ›</span>')
    else:
        detail = "".join(f"<code>{escape(x)}</code>" for x in f["examples"][:3])
        if not sessions_by_finding and OLD_FILES[0]:
            detail += '<p class="nosess">Sessions show here when the files come from a newer collector.</p>'
    machines = chips_of(on, 4) if len(on) > 1 else f'<span class="chip">{escape(on[0])}</span>' if on else ""
    return (f'<div class="dwi"{" data-has" if ids else ""}><div class="h"><span class="pill {f["severity"]}"><span class="d"></span>{SEV_WORD[f["severity"]]}</span>'
            f'<b>{escape(f["label"])}</b><span>{f["count"]:,}<small>{noun(f["count"], "time")}</small></span></div>'
            f'<div class="on"><span class="muted">On {plural(len(on), "machine")}</span> {machines}</div>{detail}</div>')


def sessions_line(m, sessions_by_finding):
    records = m.get("session_records") or []
    if not records or not sessions_by_finding:
        return ""
    severity = {f"{k[0]}:{k[1]}": f["severity"] for k, f in m["findings"].items() if not f["local_only"]}
    risky = sum(1 for r in records if any(severity.get(x["id"]) in ("high", "medium") for x in r["findings"]))
    return (f'<div class="seslink">{icon("history")}<span><b>{len(records):,}</b> {noun(len(records), "session")} had a medium- '
            f'or high-risk action or a write operation; <b>{risky:,}</b> ran or tried a medium- or high-risk one.</span>'
            f'<span class="dwlink" data-dw="sessions" data-arg="*" data-label="" tabindex="0" role="button">See the sessions ›</span></div>')


def risky_section(m, rep, panels, sessions_by_finding):
    per, n_end = m["per_endpoint"].values(), rep["endpoints"]
    group = {g: sum(x["risky_actions"] == g for x in per) for g in ("high", "medium", "none")}
    tones = (("high", "hi", "var(--risk-high)"), ("medium", "md", "var(--risk-med)"), ("none", "no", "var(--line)"))
    fleet = '<div class="fbar" role="img" aria-label="Machines by their worst risky action">' + "".join(
        f'<span style="width:{100 * group[g] / n_end:.3f}%;background:{col}"></span>' for g, _, col in tones if group[g]) + "</div>"
    key = (f'<div class="fk"><span><b class="hi">{group["high"]:,}</b>of {plural(n_end, "machine")} ran or tried a high-risk action</span>'
           f'<span><b class="md">{group["medium"]:,}</b>a medium-risk one at most</span><span><b>{group["none"]:,}</b>none</span></div>')
    tactics = tactic_counts(rep)
    if not tactics:
        matrix = '<p class="muted">No high- or medium-risk action.</p>'
    else:
        mx = {s: max([d[s] for _, d in tactics] + [1]) for s in ("high", "medium")}
        rows = []
        for i, (t, d) in enumerate(tactics):
            ic, lab = TACTIC_PLAIN.get(t, ("alert", t))
            attr = panel(panels, f"tactic-{i}", lab, f"MITRE ATT&CK tactic: {t} · {d['high']:,} high, {d['medium']:,} medium"
                         + (ONCE_PER_SESSION if m["per_session"] else ""),
                         "".join(finding_card(f, sessions_by_finding) for f in d["findings"]))
            cells = "".join(
                f'<td class="rb {s}"><span class="bb" style="width:{max(3, 100 * d[s] / mx[s]):.1f}%"></span><b>{d[s]:,}</b></td>'
                if d[s] else '<td class="rb"><span class="z">–</span></td>' for s in ("high", "medium"))
            on_n = f"{len(d['on']):,}" if n_end > 1 else ""
            rows.append(f'<tr{attr}><td class="rl"><div>{icon(ic)}<span>{escape(lab)}<em>ATT&amp;CK: {escape(t)}</em></span></div></td>{cells}'
                        f'<td class="num muted">{on_n}<span class="chev">›</span></td></tr>')
        matrix = ('<table class="rmx"><tr><th></th><th><span class="pill high"><span class="d"></span>High<span class="hs"> risk</span></span></th>'
                  '<th><span class="pill medium"><span class="d"></span>Medium<span class="hs"> risk</span></span></th>'
                  + ('<th class="num">Machines</th>' if n_end > 1 else '<th></th>') + '</tr>'
                  + "".join(rows) + "</table>")
    return ('<section class="panel" id="risky"><div class="k">01</div><h2>Agents ran or tried risky actions.</h2>'
            + (f'<div class="fleet-row">{fleet}{key}</div>' if n_end > 1 else "")
            + f'{matrix}{sessions_line(m, sessions_by_finding)}{all_actions(rep, sessions_by_finding)}</section>')


def all_actions(rep, sessions_by_finding=None):
    items = rep["findings"] + rep["local"]
    if not items:
        return ""
    d = rep["dimensions"]["risky_actions"]["session_groups"]
    total = sum(d.values()) or 1
    cols = (("None", "var(--line)", "No risky action"), ("Medium-risk", "var(--risk-med)", "At least one medium-risk action"),
            ("High-risk", "var(--risk-high)", "At least one high-risk action"))
    bar = '<div class="sbars">' + "".join(f'<span style="width:{100 * d[g] / total:.3f}%;background:{c}"></span>' for g, c, _ in cols if d[g]) + "</div>"
    skey = '<div class="skey">' + "".join(f'<span><i style="background:{c}"></i>{w}: <b>{d[g]:,}</b></span>' for g, c, w in cols) + "</div>"
    rows, n = [], 0
    rank = {"high": 0, "medium": 1, "low": 2}
    for title, group in (("High risk", [f for f in rep["findings"] if f["severity"] == "high"]),
                         ("Medium risk", [f for f in rep["findings"] if f["severity"] == "medium"]),
                         ("Low risk", [f for f in rep["findings"] if f["severity"] == "low"]),
                         ("Only on the developer’s own machine", rep["local"])):
        if not group:
            continue
        rows.append(f'<tr class="sub"><td colspan="{5 if sessions_by_finding else 4}">{title}</td></tr>')
        for f in group:
            n += 1
            key = f"{f['source']}:{f['id']}"
            on = sorted(f["endpoints"])
            rows.append(f'<tr data-k="{escape(f["label"].lower())}|{rank[f["severity"]]}|{f["count"]}|{len(on)}">'
                        f'<td><b>{escape(f["label"])}</b><div class="tech">ATT&amp;CK: {escape(f["tactic"])}</div>'
                        f'<div class="ex">{"".join(f"<code>{escape(x)}</code>" for x in f["examples"][:3])}</div></td>'
                        f'<td><span class="pill {f["severity"]}"><span class="d"></span>{SEV_WORD[f["severity"]]}</span></td>'
                        f'<td class="num">{f["count"]:,}<div class="muted">{plural(len(on), "machine")}</div></td><td>{chips_of(on, 4)}</td>'
                        + (f'<td class="ses">{session_link(key, f["label"], sessions_by_finding.get(key, []))}</td>'
                           if sessions_by_finding else "") + '</tr>')
    lows = sum(f["count"] for f in rep["findings"] if f["severity"] == "low")
    local = sum(f["count"] for f in rep["local"])
    note = ("The counts above are the high- and medium-risk ones. This table also lists "
            + joined([x for x in (f"{lows:,} low-risk {noun(lows, 'action')}" if lows else "",
                                  f"{local:,} that only touched the machine’s own copy of the code" if local else "") if x])
            + ".") if lows or local else ""
    return (f'<details class="more"><summary>See every risky action, with the commands</summary><div>'
            f'<p class="muted">Counted by session: {plural(total, "session")}</p>{bar}{skey}'
            + (f'<p class="muted">{note}</p>' if note else "")
            + '<div class="scroll"><table class="all"><tr class="sorth"><th data-col="0" aria-sort="none">What the agent did</th>'
              '<th data-col="1" aria-sort="none">Risk</th><th data-col="2" aria-sort="none" class="num">How often</th>'
              '<th data-col="3" aria-sort="none">On which machines</th>'
            + ('<th>Sessions</th>' if sessions_by_finding else "") + '</tr>' + "".join(rows) + "</table></div></div></details>")


def accessed(m):
    out = {}
    for kind in KINDS:
        xs = [x for x in m["resources"][kind].values() if x["reads"] or x["changes"] or x["calls"] or x.get("conversation")]
        if xs:
            out[kind] = sorted(xs, key=lambda x: (not counts_change(kind, x), -x["changes"], -(x["reads"] + x["calls"]),
                                                  unnamed(kind, x), x["name"]))
    return out


def systems_panel(rep, by_kind, kinds, sessions_by_system, cap=300):
    out = []
    for k in kinds:
        xs = by_kind[k]
        chg = [x for x in xs if counts_change(k, x)]
        rest = [x for x in xs if not counts_change(k, x)]

        def name(x):
            talk = x.get("conversation")
            said = f'<div class="muted">{plural(talk, "comment or review", "comments or reviews")}</div>' if talk else ""
            return f"{system_name(k, x)}{said}"

        def writes(x):
            if not sessions_by_system:
                return ""
            key = f"{k}:{x['name']}"
            shown = UNNAMED_AS[k][1] if unnamed(k, x) else x["name"]
            return f'<td class="ses">{session_link(key, shown, sessions_by_system.get(key, []), True)}</td>'
        head = f'<span class="sgn">{escape(SYSTEM[k][1])}</span>' if len(kinds) > 1 else ""
        part = [head]
        if chg:
            part.append(f'<p class="sgh">Written to: {len(chg):,}</p><table><tr><th>System</th><th class="num">Write operations</th>'
                        + ('<th>Sessions</th>' if sessions_by_system else "") + '</tr>'
                        + "".join(f'<tr><td>{name(x)}</td><td class="num">{x["changes"]:,}</td>{writes(x)}</tr>' for x in chg[:cap])
                        + (f'<tr><td colspan="{3 if sessions_by_system else 2}" class="muted">And {len(chg) - cap:,} more in the facts file.</td></tr>'
                           if len(chg) > cap else "") + "</table>")
        if rest:
            word = "Commands run, not sorted into reads and writes" if k == "ssh" else "Read only"
            chips = "".join(f'<span class="chip acc">{escape(UNNAMED_AS[k][1] if unnamed(k, x) else x["name"])}'
                            + (f' · {plural(x["conversation"], "comment or review", "comments or reviews")}'
                               if x.get("conversation") else "") + '</span>' for x in rest[:cap])
            if len(rest) > cap:
                chips += f'<span class="chip more">+{len(rest) - cap:,} more in the facts file</span>'
            part.append(f'<p class="sgh">{word}: {len(rest):,}</p><div class="chips">{chips}</div>')
        out.append(f'<div class="sg">{"".join(part)}</div>')
    talked = any(x.get("conversation") for k in kinds for x in by_kind[k])
    return (("<p class=\"muted\">Comments, reviews, reactions, labels and issues are counted apart, not as write operations.</p>"
             if talked else "") + "".join(out))


def systems_section(m, rep, panels, sessions_by_system):
    by_kind = accessed(m)
    if not by_kind:
        return ('<section class="panel" id="systems"><div class="k">02</div><h2>Agents didn’t access your systems.</h2>'
                '<p class="muted">No repository, cloud account, cluster, registry, server, website or SaaS tool.</p></section>')
    total = {k: len(xs) for k, xs in by_kind.items()}
    moved = {k: sum(bool(counts_change(k, x)) for x in xs) for k, xs in by_kind.items()}
    cats = []
    for cname, cicon in CATEGORIES:
        mem = sorted((k for k in by_kind if SYSTEM[k][2] == cname), key=lambda k: (-total[k], -moved[k]))
        if mem:
            cats.append((cname, cicon, mem, sum(total[k] for k in mem)))
    cats.sort(key=lambda c: -c[3])
    grand = sum(c[3] for c in cats)
    n_changed = sum(moved.values())
    W, LX, XM, TX, SPAN = 980, 190, 430, 640, 170
    wof = lambda n: max(2.0, n * SPAN / grand)
    y, leaves = 30.0, []
    for ci, (_, _, mem, _) in enumerate(cats):
        if len(mem) > 1:
            y += 22
        for k in mem:
            h = max(28, wof(total[k]))
            leaves.append((ci, k, y + h / 2))
            y += h + 18
        y += 10
    H = int(y + 6)
    LY = H / 2
    on = len({e for xs in by_kind.values() for x in xs for e in x["endpoints"]})

    def band(xa, xb, k, top_a, top_b):
        w = wof(total[k])
        return link(xa, top_a + w / 2, xb, top_b + w / 2, w, "").replace(' class=""', "")

    out = [f'<svg viewBox="0 0 {W} {H}" class="flow" role="img" aria-label="Systems agents accessed, by kind and provider, and how many they wrote to">']
    src = LY - sum(wof(c[3]) for c in cats) / 2
    bands = []
    for ci, (cname, _, mem, ctot) in enumerate(cats):
        ys = [ly for c, _, ly in leaves if c == ci]
        wc = sum(wof(total[k]) for k in mem)
        if len(mem) == 1:
            k = mem[0]
            # Kept at its own height so it never crosses the other branches.
            bands.append(band(LX + 8, XM, k, src, ys[0] - wc / 2))
            bands.append(band(XM, TX - 12, k, ys[0] - wc / 2, ys[0] - wc / 2))
            src += wc
            continue
        my = sum(ys) / len(ys)
        a, b = src, my - wc / 2
        for k, ty in zip(mem, ys):
            w = wof(total[k])
            bands.append(band(LX + 8, XM, k, a, b))
            bands.append(band(XM + 5, TX - 12, k, b, ty - w / 2))
            a += w; b += w
        src += wc
        cmoved = sum(moved[k] for k in mem)
        attr = panel(panels, f"cat-{ci}", cname, f"{ctot:,} accessed · {cmoved:,} written to", systems_panel(rep, by_kind, mem, sessions_by_system))
        out.append(f'<rect x="{XM}" y="{my - wc / 2 - 3:.1f}" width="5" height="{wc + 6:.1f}" class="ink"/>'
                   f'<g{attr}><text x="{XM + 2}" y="{my - wc / 2 - 10:.1f}" text-anchor="middle" class="fn">{escape(cname)}: '
                   f'<tspan class="fl">{ctot:,}</tspan></text></g>')
    out.insert(1, f'<g class="bands">{"".join(bands)}</g>')
    for _, k, ty in leaves:
        sub = f"{moved[k]:,} written to" if moved[k] else "commands run" if k == "ssh" else "none written to"
        attr = panel(panels, f"kind-{k}", SYSTEM[k][1], f"{total[k]:,} accessed · {moved[k]:,} written to",
                     systems_panel(rep, by_kind, [k], sessions_by_system))
        out.append(f'<g{attr}><rect x="{TX - 6}" y="{ty - 18:.1f}" width="{W - TX}" height="36" class="hit"/>'
                   + ficon(SYSTEM[k][0], TX, ty - 13)
                   + f'<text x="{TX + 34}" y="{ty + 5:.1f}" class="fn">{escape(SYSTEM[k][1])}: {total[k]:,} '
                   f'<tspan class="fl">· {sub}</tspan></text></g>')
    out.append(f'<line x1="{LX + 8}" y1="{LY - SPAN / 2 - 8:.1f}" x2="{LX + 8}" y2="{LY + SPAN / 2 + 8:.1f}" class="ink" style="stroke:var(--ink)" stroke-width="2"/>'
               + ficon("laptop", LX - 40, LY - 52, 30, "mu")
               + f'<text x="{LX - 6}" y="{LY - 4:.1f}" text-anchor="end" class="fn">Agents on {on:,} of {rep["endpoints"]:,}</text>'
               f'<text x="{LX - 6}" y="{LY + 16:.1f}" text-anchor="end" class="fl">{noun(rep["endpoints"], "machine")} accessed</text>'
               f'<text x="{LX - 6}" y="{LY + 34:.1f}" text-anchor="end" class="fl">{plural(grand, "system")}</text></svg>')
    title = ("Systems your agents accessed and wrote to" if n_changed
             else "Systems your agents accessed. They wrote to none of them.")
    return (f'<section class="panel" id="systems"><div class="k">02</div><h2>{title}</h2>'
            f'<div class="flowbox">{"".join(out)}</div></section>')


def guardrails_section(m, rep, panels):
    total, blind = m["commands"], m["other_code_commands"]
    if not total:
        return ""
    learn = LEARN_MORE
    rest = total - blind
    kinds = [(k, n) for k, n in most_first(m["other_code"]) if n]
    kinds_list = '<div class="kl">' + "".join(
        f'<div class="kr"><div class="kh"><b>{escape(OTHER_CODE_NAMES.get(k, k)[:1].upper() + OTHER_CODE_NAMES.get(k, k)[1:])}</b>'
        f'<span>{share(n, blind)}</span></div>'
        f'<div class="kbar"><span style="width:{max(0.8, 100 * n / blind):.2f}%"></span></div>'
        f'<div class="kd">{escape(OTHER_CODE_WHAT.get(k, ("", ()))[0])}<span class="n">{plural(n, "command")}</span></div>'
        f'<div class="kx">{"".join(f"<code>{escape(x)}</code>" for x in OTHER_CODE_WHAT.get(k, ("", ()))[1])}</div></div>'
        for k, n in kinds) + '</div><p class="muted kn">A command can be more than one kind, so the shares can add up to more than 100%.</p>'
    blind_attr = panel(panels, "blind", "Started other code", f"{plural(blind, 'command')} · {share(blind, total)} of all {total:,}",
                       "<p>Agent policies see only the command, such as <code>npm test</code>, not what the code it "
                       "started then did. By kind of code:</p>" + kinds_list
                       + f'<a class="lm" href="{escape(learn)}" target="_blank" rel="noopener">Learn more</a>')
    RW, OX, TX, SPAN = 980, 46, 440, 210
    wB, wR = max(1.5, blind * SPAN / total), max(1.5, rest * SPAN / total)
    X0 = OX + 100
    b_top = 46.0
    a_top = b_top + wB + 46
    ry = a_top + wR / 2
    RH = int(a_top + max(wR, 56) + 30)
    s_top = (b_top + a_top + wR) / 2 - (wR + wB) / 2
    out = [f'<svg viewBox="0 0 {RW} {RH}" class="flow" role="img" aria-label="All agent commands: those that started other code, which agent policies cannot check, and the rest">']
    out.append(link(X0, s_top + wB / 2, TX - 40, b_top + wB / 2, wB, "").replace('class=""', 'style="fill:none;stroke:url(#hz)"'))
    out.append(f'<g{blind_attr}><rect x="{TX - 34}" y="{b_top + wB / 2 - 26:.1f}" width="{380}" height="52" class="hit"/>'
               f'<circle cx="{TX - 6}" cy="{b_top + wB / 2:.1f}" r="26" style="fill:var(--panel);stroke:var(--risk-med)" stroke-width="2.5"/>'
               f'<text x="{TX - 6}" y="{b_top + wB / 2 + 10:.1f}" text-anchor="middle" class="qm">?</text>'
               f'<text x="{TX + 34}" y="{b_top + wB / 2 + 5:.1f}" class="fn">Started other code: {blind:,} {noun(blind, "command")}</text></g>')
    out.append(link(X0, s_top + wB + wR / 2, TX - 12, ry, wR, "pale")
               + ficon("laptop", TX, ry - 13, 24, "mu")
               + f'<text x="{TX + 34}" y="{ry - 3:.1f}" class="fn quiet">Everything else: {rest:,} {noun(rest, "command")}</text>'
               f'<text x="{TX + 34}" y="{ry + 17:.1f}" class="fl">the command itself shows what it does</text>')
    BX = 846
    brace = lambda y1, y2, col: (f'<path d="M{BX},{y1:.1f} q9,0 9,9 L{BX + 9},{(y1 + y2) / 2 - 9:.1f} q0,9 9,9 q-9,0 -9,9 '
                                 f'L{BX + 9},{y2 - 9:.1f} q0,9 -9,9" style="fill:none;stroke:{col}" stroke-width="1.6" stroke-linecap="round"/>')
    label = lambda y1, y2, a, b, cls: (f'<text x="{BX + 26}" y="{(y1 + y2) / 2 - 4:.1f}" class="{cls}">{a}</text>'
                                       f'<text x="{BX + 26}" y="{(y1 + y2) / 2 + 14:.1f}" class="{cls}">{b}</text>')
    yb1, yb2 = b_top + wB / 2 - max(28, wB / 2), b_top + wB / 2 + max(28, wB / 2)
    ya1, ya2 = ry - max(28, wR / 2), ry + max(28, wR / 2)
    out.append(brace(yb1, yb2, "var(--risk-med)") + label(yb1, yb2, "Invisible to", "agent policies", "fork-b"))
    out.append(brace(ya1, ya2, "var(--line)") + label(ya1, ya2, "Visible to", "agent policies", "fork-a"))
    OY = s_top + (wR + wB) / 2
    out.append(f'<rect x="{X0 - 6}" y="{s_top:.1f}" width="6" height="{wR + wB:.1f}" class="ink"/>' + ficon("laptop", OX - 8, OY - 26, 52, "mu")
               + f'<text x="{OX + 18}" y="{OY + 46:.1f}" text-anchor="middle" class="fl">{plural(total, "command")}</text>'
               f'<text x="{OX + 18}" y="{OY + 64:.1f}" text-anchor="middle" class="fl">on {plural(rep["endpoints"], "machine")}</text></svg>')
    quarter = share(blind, total)
    return (f'<section class="panel" id="guardrails"><div class="k">03</div>'
            f'<h2>{quarter} of what agents executed couldn’t be evaluated with confidence using the native guardrails.</h2>'
            '<p class="muted">These commands started other code, such as a script, a build or a test. A guardrail sees '
            'only the command, so judging what that code did needs its runtime context.</p>'
            f'<div class="flowbox">{"".join(out)}</div>'
            f'<div class="big"><span class="q" aria-hidden="true">?</span><b>{blind:,}</b><div><div class="t">agent {noun(blind, "command")} started other code</div>'
            f'<div class="s">{share(blind, total)} of all {plural(total, "command")}.</div></div>'
            f'<a class="lm" href="{escape(learn)}" target="_blank" rel="noopener">Learn more</a></div></section>')


def share(part, whole):
    """A share that never reads 0% for a count above zero: one decimal from 1%, two significant digits below."""
    if not whole:
        return "0%"
    p = 100 * part / whole
    return f"{p:.1f}%" if p >= 1 else f"{p:.2g}%"


def session_data(m, with_sessions):
    """The session records and what the page needs to show them, as a JSON block that is never run."""
    if not with_sessions or not m.get("session_records"):
        return "", {}, {}
    by_finding = {f"{k[0]}:{k[1]}": f.get("sessions", []) for k, f in m["findings"].items() if f.get("sessions")}
    by_system = collections.defaultdict(set)
    for r in m["session_records"]:
        for c in r["changes"]:
            x = m["resources"][c["kind"]].get(c["name"])
            if x and counts_change(c["kind"], x):
                by_system[f"{c['kind']}:{c['name']}"].add(r["id"])
    by_system = {k: sorted(v) for k, v in by_system.items()}
    names_ = {f"{k[0]}:{k[1]}": {"label": label(f), "severity": f["severity"], "local_only": f["local_only"]}
              for k, f in m["findings"].items()}
    records = {r["id"]: dict({k: v for k, v in r.items() if k not in ("claude_code_version", "codex_version")},
                             agent=AGENT_NAMES[r.get("agent", "claude-code")])
               for r in m["session_records"]}
    payload = {"records": records, "by_finding": by_finding, "by_system": by_system, "mixed": len(m["agents"]) > 1,
               "names": names_, "unnamed": sorted(UNNAMED),
               "unnamed_as": {k: v[1] for k, v in UNNAMED_AS.items()},
               "kinds": SYSTEM_ONE}
    # Escape every "<": "</script" or "<!--<script" in a logged command would break out of the block.
    text = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).replace("<", "\\u003c")
    return f'<script type="application/json" id="session-data">{text}</script>', by_finding, by_system


def agent_chips(m):
    """One chip per agent with sessions in the files: its name and how many sessions."""
    chips = "".join(f'<span class="chip agent">{escape(AGENT_NAMES[a])} · <b>{n:,}</b> {noun(n, "session")}</span>'
                    for a, n in m["agents"].items())
    return f'<div class="chips agents">{chips}</div>' if chips else ""


STARTS_OTHER = "When a command starts other code, such as a build or a script, they don't see what that code does"
SANDBOX = "Codex's sandbox, when on, still limits what that code can write or reach."
POLICIES = {
    "claude-code": f"Claude Code's permission rules and hooks see each command. {STARTS_OTHER}.",
    "codex": f"Codex's approval rules see each command. {STARTS_OTHER}; {SANDBOX}",
    "mixed": f"Claude Code's permission rules and hooks, and Codex's approval rules, see each command. "
             f"{STARTS_OTHER}; {SANDBOX}",
}


def policies(m):
    agents = list(m["agents"])
    return POLICIES["mixed" if len(agents) > 1 else agents[0] if agents else "claude-code"]


def html_report(m, org, rep, with_sessions=True):
    template = shipped("templates/report.html").decode("utf-8")
    page = PART.sub("", template)
    script = re.findall(r"<script>(.*?)</script>", page, re.S)[-1]
    panels = {}
    data, by_finding, by_system = session_data(m, with_sessions)
    OLD_FILES[0] = with_sessions and not m.get("session_records")
    unread, large = rep["unread"], rep["large"]
    values = {"font_css": font_css(), "logo_svg": logo_svg(), "org": org or "assessment", "org_name": org or "",
              "script_hash": base64.b64encode(hashlib.sha256(script.encode()).digest()).decode(),
              "agent_chips": agent_chips(m), "policies": policies(m),
              "made": rep["made"],
              "collected": " to ".join(dict.fromkeys((m["collected"][0][:10], m["collected"][-1][:10]))),
              "machines": f"{rep['endpoints']:,}", "machines_word": noun(rep["endpoints"], "machine"),
              "activity": " – ".join(map(day, dict.fromkeys(m["span"]))) if m["span"] else rep["span"].capitalize(),
              "idle": rep["idle"],
              "read_problems": "".join(f"<li>{escape(t)}</li>" for t in (unread, large) if t),
              "figures": head_and_figures(m, rep), "risky": risky_section(m, rep, panels, by_finding),
              "systems": systems_section(m, rep, panels, by_system),
              "guardrails": guardrails_section(m, rep, panels),
              "panels": "".join(f'<template id="dw-{escape(i)}" data-title="{escape(t)}" data-sub="{escape(s)}">{inner}</template>'
                                for i, (t, s, inner) in panels.items()),
              "session_data": data}
    return fill(page, values)


def developer_ids(m):
    """Opaque stable IDs (dev-1, dev-2…) ordered by a hash, so the facts never pair endpoint and user."""
    digest = lambda u: hashlib.sha256("\0".join(u).encode()).hexdigest()
    users = set(m["users"]).union(*(f["users"] for f in m["findings"].values()),
                                  *(x["users"] for kind in KINDS for x in m["resources"][kind].values()))
    return {u: f"dev-{i}" for i, u in enumerate(sorted(users, key=digest), 1)}


def facts(m, rep, skipped, dropped):
    """The merged facts for follow-up questions; developers are opaque IDs, never paired with a machine."""
    ids = developer_ids(m)
    devs = lambda users: sorted((ids[u] for u in users), key=lambda d: int(d[4:]))

    def finding(f):
        return dict(f, endpoints=sorted(f["endpoints"]),
                    times_by_endpoint=dict(sorted(f["endpoints"].items())), users=devs(f["users"]))

    def resource(x):
        return dict(x, endpoints=sorted(x["endpoints"]),
                    uses_by_endpoint=dict(sorted(x["endpoints"].items())),
                    users=devs(x["users"]), services=dict(sorted(x["services"].items())),
                    tools=dict(sorted(x["tools"].items())), profiles=sorted(x["profiles"]))
    return {
        "org": rep["org"], "made": rep["made"], "days": m["days"],
        "collected": {"from": m["collected"][0], "to": m["collected"][-1]},
        "endpoints": m["endpoints"], "developers": len(m["users"]), "sessions": m["sessions"],
        "developer_ids": devs(m["users"]),
        "totals": dict(sorted(m["totals"].items())), "errors": dict(m["errors"]),
        "groups": dict(rep["dimensions"], endpoints={n: dict(x, risky_actions=GROUP_NAMES[x["risky_actions"]],
                                                                 changes=GROUP_NAMES[x["changes"]])
                                                    for n, x in sorted(m["per_endpoint"].items())}),
        "findings": {f"{f['source']}:{f['id']}": finding(f) for f in rep["findings"]},
        "local_only": {f"{f['source']}:{f['id']}": finding(f) for f in rep["local"]},
        "notable_actions": [f"{f['source']}:{f['id']}" for f in rep["shown"]],
        "changed_assets": rep["changed_assets"], "activity": rep["span"],
        "local_mcp_servers": rep["local_mcp"], "ai_api_hosts": rep["ai_apis"],
        "rare_destinations": len(rep["rare"]) if rep["endpoints"] > 1 else None,
        "endpoints_in_unread_format": m["unread_format"], "endpoints_without_activity": m["idle"],
        "risky_by_severity": rep["by_severity"], "risky_counted_once_per_session": m["per_session"],
        "resources": {kind: {n: resource(x) for n, x in m["resources"][kind].items()} for kind in KINDS},
        "other_code": dict(sorted(m["other_code"].items())), "other_code_commands": m["other_code_commands"],
        "commands": m["commands"], "other_code_share": rep["other_code_share"],
        "visible_changes": m["visible_changes"],
        "format": {k: dict(sorted(v.items())) if isinstance(v, collections.Counter) else v
                   for k, v in m["format"].items()},
        "files_skipped": [{"file": n, "why": w} for n, w in skipped],
        "files_dropped_as_older": [{"file": n, "why": w} for n, w in dropped],
        "session_records": m["session_records"],
        "sessions_by_agent": m["agents"],
    }


def digest(m, rep, html_path, json_path, skipped, dropped):
    """A short text summary; endpoint strings are JSON-quoted, as data, not instructions."""
    q = lambda s: json.dumps(s, ensure_ascii=False)
    per = sorted(m["per_endpoint"].items(), key=lambda nx: (
        RISK_GROUPS.index(nx[1]["risky_actions"]), CHANGE_GROUPS.index(nx[1]["changes"]), -nx[1]["commands"],
        nx[0]))
    errors = m["errors"]
    out = [f"report: {html_path}", f"facts:  {json_path}",
           f"endpoints {len(m['endpoints'])} · developers {len(m['users'])} · "
           f"commands {m['totals']['shell_commands']:,}"]
    if m["agents"]:
        out.append("sessions by agent: " + " · ".join(f"{AGENT_NAMES[a]} {n:,}" for a, n in m["agents"].items()))
    for d in rep["dimensions"].values():
        out.append(f"{d['title'].lower()}: " + "; ".join(filter(None, d["says"].values()))
                   + "; machines " + " · ".join(f"{n} {g}" for g, n in d["machine_groups"].items())
                   + "; sessions " + " · ".join(f"{n} {g}" for g, n in d["session_groups"].items()))
    out.append("per endpoint, worst first (name · worst risky action · changed · commands): " + "; ".join(
        f"{q(n)} {GROUP_NAMES[x['risky_actions']]} / {GROUP_NAMES[x['changes']]} / {x['commands']}"
        for n, x in per[:DIGEST_MACHINES])
        + (f"; {len(per) - DIGEST_MACHINES:,} more in the facts" if len(per) > DIGEST_MACHINES else ""))
    kinds = ", ".join(f"{k if k in OTHER_CODE_NAMES else q(k)} {v}" for k, v in most_first(m["other_code"]))
    out.append(f"executed other code {m['other_code_commands']:,} of {m['commands']:,}: {kinds or 'none'}"
               + ("; started no other code and changed (first kind): "
                  + " · ".join(f"{k} {n:,}" for k, n in m["visible_changes"].items()) if m["visible_changes"] else ""))
    if any(errors.values()):
        out.append(f"unreadable on the endpoints: {plural(errors['homes_skipped'], 'home folder')}, "
                   f"{plural(errors['files_skipped'], 'log file')}, "
                   f"{plural(errors['calls_skipped'], 'entry', 'entries')} with commands; passed over: "
                   f"{plural(errors['large_entries_skipped'], 'very large entry', 'very large entries')} without commands")
    if m["unread_format"]:
        machines = ", ".join(q(h) for h in m["unread_format"])
        out.append("logs not in a format the collector reads, on "
                   f"{plural(len(m['unread_format']), 'endpoint')}: {machines}")
    out.append("risky actions (label · tactic · risk · times · sessions · endpoints · developers · coverage · example):"
               if rep["findings"] else "risky actions: none")
    for f in rep["findings"]:
        out.append(f"  {q(f['label'])} · {f['tactic']} · {f['severity']} · {f['count']} · {f['session_count']} · "
                   f"{len(f['endpoints'])} · {len(f['users'])} · {f['coverage']} · {q(f['examples'][0])}")
    if rep["local"]:
        out.append("local only, no risk group (label · times · endpoints):")
    for f in rep["local"]:
        out.append(f"  {q(f['label'])} · {f['count']} · {len(f['endpoints'])}")
    for kind in KINDS:
        top5 = sorted(m["resources"][kind].values(),
                      key=lambda x: (-x["changes"], -x["calls"], -x["reads"], x["name"]))[:5]
        if top5:
            out.append(f"{kind}: " + "; ".join(f"{q(x['name'])} r{x['reads']}/c{x['changes']}"
                                              + (f"/calls{x['calls']}" if x["calls"] else "")
                                              + (f"/conversation{x['conversation']}" if x.get("conversation") else "")
                                              for x in top5))
    if skipped:
        out.append("skipped: " + "; ".join(f"{q(n)} ({w})" for n, w in skipped))
    if dropped:
        out.append("older duplicates, not counted: " + "; ".join(f"{q(n)} ({q(w)})" for n, w in dropped))
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(prog=f"{os.path.basename(sys.argv[0])} report",
                                     description="Merge endpoint files into one organisation report (HTML).")
    parser.add_argument("folder", nargs="?", default=os.path.join(HERE, FILES_FOLDER),
                        help="the endpoint files; default: agent-activity-files next to this file")
    parser.add_argument("--out", help="the HTML report; default: agent-activity-report.html in the folder")
    parser.add_argument("--org", help="the organisation's name, for the title")
    parser.add_argument("--no-sessions", action="store_true",
                        help="leave the session records out of the page (they stay in the facts)")
    args = parser.parse_args(argv)
    utf8_output()
    if not os.path.isdir(args.folder):
        sys.exit(f"{args.folder} is not a folder.")
    if not os.access(args.folder, os.R_OK | os.X_OK):
        sys.exit(f"Can't read {args.folder}. Files saved as root need sudo: "
                 f"sudo sh agent-activity.py report \"{args.folder}\"")
    files, skipped, dropped = load(args.folder)
    if not files:
        listed = "; ".join(f"{json.dumps(n)} ({w})" for n, w in skipped)
        sys.exit(f"No endpoint files in {args.folder}." + (f"\nskipped: {listed}" if skipped else ""))
    org = clean(args.org) if args.org else None
    # Idle machines are left out of every count, unless all are idle.
    active = [f for f in files if assessable(f)] or files
    merged = merge(active)
    merged["idle"] = sorted(f["endpoint"]["name"] for f in files if not any(f is a for a in active))
    rep = report(merged, org)
    html_path = pathlib.Path(args.out or pathlib.Path(args.folder) / "agent-activity-report.html").resolve()
    json_path = html_path.with_name(html_path.stem + ".facts.json")
    try:
        html_path.write_text(html_report(merged, org, rep, not args.no_sessions), encoding="utf-8")
        merged_facts = facts(merged, rep, skipped, dropped)
        json_path.write_text(json.dumps(merged_facts, indent=1, sort_keys=True, default=sorted) + "\n",
                             encoding="utf-8")
    except OSError as error:
        sys.exit(f"Couldn't write the report: {error.strerror} ({error.filename}).")
    print(digest(merged, rep, html_path, json_path, skipped, dropped))
    if sys.stdout.isatty():
        show(html_path)


def show(path):
    if sys.platform == "darwin":
        subprocess.run(["/usr/bin/open", str(path)], check=False)
    elif os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        try:
            subprocess.run(["xdg-open", str(path)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


if __name__ == "__main__":
    main()
