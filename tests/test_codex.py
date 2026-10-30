"""Codex CLI rollouts: what the collector reads from them, what it never keeps,
and the report on Claude Code and Codex files together."""

import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from html import unescape

import support
import collect
from support import findings, resources

SECRETS = ("PROMPT-SECRET-TEXT", "MODEL-OUTPUT-TEXT", "REASONING-TEXT", "QUERY-TEXT", "OUTPUT-TEXT",
           "ARG-SECRET-TEXT", "ENV-SECRET-VALUE", "HISTORY-TEXT", "AUTH-SECRET-VALUE", "CONFIG-SECRET-VALUE",
           "PLAN-TEXT", "FILE-CONTENT-TEXT", "INSTRUCTIONS-TEXT", "Begin Patch", "evil.example", "file://", "0199",
           support.AWS_KEY, "wJalrXUtnFEMI")


class Collect(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data, cls.text, cls.home = support.collect("codex")

    def test_findings_across_tactics(self):
        # The same rules as for Claude Code: a legacy rollout (tool calls and end events), its
        # subagent, and a newer paginated one (completed items).
        self.assertEqual(findings(self.data), {
            ("own", "force-push:default-branch"): 1,
            ("pathfinding.cloud", "iam-002"): 1,
            ("own", "download-run:unknown"): 1,
            ("claude-code-safety-net", "personal-credentials:credentials"): 1,
            ("own", "keychain-read"): 1,
            ("shellfirm", "kubernetes:delete_namespace"): 1,
            ("shellfirm", "github:repo_delete"): 1,
            ("own", "file-uploaded"): 1,
            ("own", "scheduled-job"): 1,
            ("own", "setuid-set"): 1,
            ("own", "hooks-bypassed"): 1,
        })
        tactics = {f["tactic"] for f in self.data["findings"]}
        self.assertEqual(tactics, {"Impact", "Privilege Escalation", "Credential Access", "Execution", "Exfiltration",
                                   "Persistence", "Defense Evasion"})

    def test_resources(self):
        # The account comes from the AWS command's output; the access key in it is never kept.
        # ChatGPT's apps, all behind one `codex_apps` server, are named by the app.
        self.assertEqual(resources(self.data, "aws", "changes", "services"), {"123456789012": (1, {"iam": 1})})
        self.assertEqual(resources(self.data, "repositories", "changes"), {"acme/app": (1,), "acme/old": (1,)})
        self.assertEqual(resources(self.data, "kubernetes", "changes"), {"prod-ctx": (1,)})
        self.assertEqual(resources(self.data, "mcp", "calls", "changes", "tools"),
                         {"linear": (2, 2, {"create_issue": 1, "save_issue": 1}), "github": (1, 1, {"create_pull_request": 1})})
        self.assertEqual(resources(self.data, "web", "reads", "changes"), {
            "docs.example.org": (1, 0), "api.example.com": (1, 0), "get.example.net": (1, 0), "transfer.sh": (0, 1)})

    def test_each_action_counts_once(self):
        # A tool call and its end event are one action, and a call without one was tried and counts;
        # a fork's copied history adds nothing; a command the user typed, input to a running command
        # and code mode's wrapper are not commands.
        user = self.data["users"][0]
        self.assertEqual((user["sessions"], user["sessions_by_agent"]), (3, {"codex": 3}))
        self.assertEqual(self.data["totals"]["shell_commands"], 12)
        self.assertEqual(self.data["format"]["codex"], {
            "versions": {"0.166.0": 2, "0.46.0": 3}, "entries": 66, "unparsed_entries": 3,
            "tool_uses": {"apply_patch": 4, "mcp": 3, "shell": 12, "update_plan": 2, "web_search": 3}})
        self.assertEqual(self.data["format"]["entries"], 0)
        self.assertEqual(self.data["totals"]["web_fetches"], 2)
        for rule in ("system-shutdown", "home-or-root-deleted"):
            self.assertNotIn(("own", rule), findings(self.data))

    def test_patches_are_not_commands(self):
        # A patch that adds `curl … | sh` and `rm -rf ~` to a file runs neither.
        examples = json.dumps([f["examples"] for f in self.data["findings"]])
        self.assertNotIn("evil.example", examples)
        self.assertNotIn("rm -rf", examples)

    def test_session_records(self):
        records = {r["started"]: r for r in self.data["sessions"]}
        self.assertEqual(sorted(records), ["2026-10-22T10:00:04.000Z", "2026-10-23T09:00:04.000Z"])
        legacy, paginated = records["2026-10-22T10:00:04.000Z"], records["2026-10-23T09:00:04.000Z"]
        self.assertEqual(set(legacy), {"id", "agent", "started", "ended", "codex_version", "project", "counts",
                                       "findings", "changes", "other_code"})
        self.assertEqual((legacy["agent"], legacy["codex_version"]), ("codex", "0.46.0"))
        self.assertRegex(legacy["id"], r"^s_[0-9a-f]{12}$")
        # The subagent's command is part of its parent's session.
        self.assertEqual(legacy["ended"], "2026-10-22T11:00:01.000Z")
        self.assertIn("shellfirm:kubernetes:delete_namespace", [f["id"] for f in legacy["findings"]])
        self.assertEqual(legacy["project"], "acme/app")
        self.assertEqual(legacy["counts"]["tool_uses"],
                         {"apply_patch": 3, "mcp": 2, "shell": 6, "update_plan": 1, "web_search": 2})
        self.assertEqual(paginated["project"], "local project")
        self.assertEqual(paginated["changes"], [{"kind": "mcp", "name": "github", "count": 1},
                                                {"kind": "repositories", "name": "acme/old", "count": 1},
                                                {"kind": "web", "name": "transfer.sh", "count": 1}])
        self.assertTrue(all(len(f["examples"]) <= 3 for r in records.values() for f in r["findings"]))

    def test_no_prompt_output_path_or_session_id(self):
        for text in SECRETS + (self.home, "/Users/", "@ROOT@"):
            self.assertNotIn(text, self.text)
        for r in self.data["sessions"]:
            self.assertFalse({"user", "users", "cwd", "folder"} & set(r))

    def test_reads_only_rollouts(self):
        home = support.FIXTURES / "codex" / "home"
        collect.OWNER.update(given=str(home), home=os.path.realpath(home), uid=os.getuid())
        names = {os.path.basename(p) for p in collect.codex_logs(str(home))}
        self.assertTrue(names and all(re.match(r"^rollout-.*\.jsonl$", n) for n in names), names)

    def test_recorded_remote_when_the_folder_has_none(self):
        def move(home):
            os.rename(home / "work" / "app", home / "work" / "gone")
        data, _, _ = support.collect("codex", move)
        self.assertIn("acme/ignored", {r["project"] for r in data["sessions"]})


class Hardening(unittest.TestCase):

    def test_links_and_other_users_files_are_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = pathlib.Path(tmp) / "other"
            (other / "sessions").mkdir(parents=True)
            stolen = json.dumps({"timestamp": "2026-10-22T10:00:00.000Z", "type": "response_item", "payload": {
                "type": "function_call", "name": "shell", "call_id": "x",
                "arguments": json.dumps({"command": ["bash", "-lc", "gh repo delete victim/x --yes"]})}})
            (other / "sessions" / "rollout-x.jsonl").write_text(stolen + "\n")

            def plant(home):
                day = home / ".codex" / "sessions" / "2026" / "10" / "24"
                (day / "rollout-link.jsonl").symlink_to(other / "sessions" / "rollout-x.jsonl")
                (home / ".codex" / "sessions" / "2026" / "11").symlink_to(other / "sessions")
                (home / ".codex" / "archived_sessions").rename(home / ".codex" / "kept")
                (home / ".codex" / "archived_sessions").symlink_to(other / "sessions")
                with open(day / "rollout-big.jsonl", "w") as handle:
                    handle.write(json.dumps({"timestamp": "2026-10-24T09:00:00.000Z", "type": "response_item",
                                             "payload": {"type": "function_call", "name": "shell",
                                                         "arguments": "x" * 2**20}}) + "\n")
                    handle.write(json.dumps({"timestamp": "2026-10-24T09:00:00.000Z", "type": "event_msg",
                                             "payload": {"type": "agent_message", "message": "x" * 2**20}}) + "\n")
            data, text, _ = support.collect("codex", plant)
        self.assertNotIn("victim", text)
        # The linked rollout and the linked archive folder; the oversized tool call is missed, the message passed over.
        self.assertEqual(data["errors"], {"homes_skipped": 0, "files_skipped": 2, "calls_skipped": 1,
                                          "large_entries_skipped": 1})

    def test_old_rollouts_are_outside_the_window(self):
        def age(home):
            for path in home.rglob("rollout-*.jsonl"):
                support.set_mtime(path, support.WINDOW_START.replace(month=9))
        data, _, _ = support.collect("codex", age)
        self.assertEqual((data["totals"]["shell_commands"], data["findings"], data["sessions"]), (0, [], []))

    def test_a_home_with_only_codex_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = support.copy_case("codex", tmp)
            done = subprocess.run([sys.executable, str(support.COLLECT), "--home", str(home), "--days",
                                   str(support.days()), "--out", "-"], capture_output=True, text=True)
        self.assertEqual(done.stderr, "")
        self.assertEqual(json.loads(done.stdout)["errors"]["homes_skipped"], 0)


def rollout(*entries):
    return "".join(json.dumps({"timestamp": t, "type": k, "payload": p}) + "\n" for t, k, p in entries)


def meta(thread, when, **more):
    return when, "session_meta", dict({"id": thread, "timestamp": when, "cwd": "/w", "cli_version": "0.147.0",
                                       "source": "cli"}, **more)


def shell(when, command, call):
    return when, "response_item", {"type": "function_call", "name": "exec_command", "call_id": call,
                                   "arguments": json.dumps({"cmd": command})}


def turn(when, turn_id):
    return when, "event_msg", {"type": "task_started", "turn_id": turn_id}


def page(when):
    return when, "response_item", {"type": "web_search_call", "status": "completed",
                                   "action": {"type": "open_page", "url": "https://docs.example.org/a"}}


def collect_rollouts(files, old=()):
    """The collector's output for a home holding these rollouts (path under ~/.codex: text);
    those in `old` are dated before the window."""
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp) / "home"
        for name, text in files.items():
            path = home / ".codex" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            if name in old:
                support.set_mtime(path, support.WINDOW_START.replace(month=8))
        out = pathlib.Path(tmp) / "out.json"
        support.run(support.COLLECT, "--home", home, "--days", support.days(), "--out", out)
        return json.loads(out.read_text(encoding="utf-8"))


# UUIDv7 ids: the parent's turn before the fork, the fork, the fork's own turn after it.
PARENT, PARENT_TURN = "019a0000-0000-7000-8000-000000000001", "019a0000-0001-7000-8000-000000000001"
FORK, FORK_TURN = "019a2000-0000-7000-8000-000000000002", "019a2000-0001-7000-8000-000000000002"


class Threads(unittest.TestCase):

    def test_subagent_named_only_in_its_source_is_its_parents_session(self):
        data = collect_rollouts({
            "sessions/2026/10/22/rollout-a.jsonl": rollout(meta(PARENT, "2026-10-22T10:00:00.000Z"),
                                                           shell("2026-10-22T10:00:01.000Z", "ls", "c1")),
            "sessions/2026/10/22/rollout-b.jsonl": rollout(
                meta(FORK, "2026-10-22T10:05:00.000Z",
                     source={"subagent": {"thread_spawn": {"parent_thread_id": PARENT, "depth": 1}}}),
                shell("2026-10-22T10:05:01.000Z", "pwd", "c2"))})
        self.assertEqual((data["users"][0]["sessions"], data["totals"]["shell_commands"]), (1, 2))

    def test_a_forks_copied_history_counts_once_and_keeps_its_date(self):
        copied = [meta(PARENT, "2026-10-25T09:00:00.000Z"), turn("2026-10-25T09:00:00.001Z", PARENT_TURN),
                  shell("2026-10-25T09:00:00.002Z", "git push --force origin main", "old1"),
                  page("2026-10-25T09:00:00.003Z")]
        fork = rollout(meta(FORK, "2026-10-25T09:00:00.000Z", forked_from_id=PARENT), *copied,
                       turn("2026-10-25T09:00:00.004Z", FORK_TURN), shell("2026-10-25T09:00:01.000Z", "ls", "new1"),
                       page("2026-10-25T09:00:02.000Z"))
        parent = rollout(meta(PARENT, "2026-08-01T09:00:00.000Z"), turn("2026-08-01T09:00:00.001Z", PARENT_TURN),
                         shell("2026-08-01T09:00:01.000Z", "git push --force origin main", "old1"),
                         page("2026-08-01T09:00:02.000Z"))
        data = collect_rollouts({"sessions/2026/10/25/rollout-f.jsonl": fork,
                                 "sessions/2026/08/01/rollout-p.jsonl": parent},
                                old={"sessions/2026/08/01/rollout-p.jsonl"})
        self.assertEqual(data["totals"]["shell_commands"], 1)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["totals"]["web_fetches"], 1)
        self.assertEqual(data["endpoint"]["first_activity"], "2026-10-25")

    def test_a_fork_without_turn_ids(self):
        fork = rollout(meta(FORK, "2026-10-25T09:00:00.000Z", forked_from_id=PARENT),
                       meta(PARENT, "2026-10-25T09:00:00.000Z"), page("2026-10-25T09:00:00.000Z"),
                       shell("2026-10-25T09:00:00.000Z", "git push --force origin main", "old1"),
                       shell("2026-10-25T09:01:00.000Z", "ls", "new1"))
        data = collect_rollouts({"sessions/2026/10/25/rollout-f.jsonl": fork})
        self.assertEqual((data["totals"]["shell_commands"], data["totals"]["web_fetches"], data["findings"]),
                         (1, 0, []))

    def test_archived_copy_counts_once(self):
        text = rollout(meta(PARENT, "2026-10-22T10:00:00.000Z"), shell("2026-10-22T10:00:01.000Z", "ls", "c1"),
                       page("2026-10-22T10:00:02.000Z"))
        data = collect_rollouts({"sessions/2026/10/22/rollout-a.jsonl": text, "archived_sessions/rollout-a.jsonl": text})
        self.assertEqual((data["totals"]["shell_commands"], data["totals"]["web_fetches"]), (1, 1))
        self.assertEqual(data["format"]["codex"]["tool_uses"], {"shell": 1, "web_search": 1})


def code(when, script, call):
    return when, "response_item", {"type": "custom_tool_call", "status": "completed", "call_id": call,
                                   "name": "exec", "input": script}


class CodeMode(unittest.TestCase):

    def test_commands_in_a_script_without_completed_items(self):
        data = collect_rollouts({"sessions/2026/10/22/rollout-a.jsonl": rollout(
            meta(PARENT, "2026-10-22T10:00:00.000Z"),
            code("2026-10-22T10:00:01.000Z", 'const r = await tools.exec_command({cmd: "git push --force origin '
                                             'main"});\ntext(r.output);', "x1"),
            code("2026-10-22T10:00:02.000Z", 'for (const t of ["a", "b"]) await tools.exec_command({cmd: `make ${t}`});',
                 "x2"),
            code("2026-10-22T10:00:03.000Z", 'await tools.update_plan({plan: []});', "x3"))})
        self.assertEqual(support.findings(data), {("own", "force-push:default-branch"): 1})
        self.assertEqual(data["totals"]["shell_commands"], 1)
        # The script built as it runs is counted, and as an entry with commands that couldn't be read.
        self.assertEqual(data["format"]["codex"]["tool_uses"], {"exec": 1, "shell": 1})
        self.assertEqual(data["errors"]["calls_skipped"], 1)

    def test_completed_items_count_instead_of_the_script(self):
        item = ("2026-10-22T10:00:02.000Z", "event_msg", {"type": "item_completed", "item": {
            "type": "CommandExecution", "id": "i1", "command": "git push --force origin main", "cwd": "/w"}})
        data = collect_rollouts({"sessions/2026/10/22/rollout-a.jsonl": rollout(
            meta(PARENT, "2026-10-22T10:00:00.000Z"),
            code("2026-10-22T10:00:01.000Z", 'await tools.exec_command({cmd: "git push --force origin main"});', "x1"),
            item)})
        self.assertEqual(support.findings(data), {("own", "force-push:default-branch"): 1})
        self.assertEqual((data["totals"]["shell_commands"], data["errors"]["calls_skipped"]), (1, 0))


def report_of(*datas, flags=()):
    """(page, facts, digest) for endpoint files host-a, host-b…"""
    with tempfile.TemporaryDirectory() as tmp:
        for i, data in enumerate(datas):
            host = f"host-{'abcdefgh'[i]}"
            data = json.loads(json.dumps(data))
            data["endpoint"] = dict(data["endpoint"], hostname=host, name=host, machine_id=host)
            (pathlib.Path(tmp) / f"{host}.json").write_text(json.dumps(data), encoding="utf-8")
        html = pathlib.Path(tmp) / "report.html"
        digest = support.run(support.REPORT, tmp, "--out", html, *flags)
        return (html.read_text(encoding="utf-8"),
                json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8")), digest)


def script_of(page):
    (script,) = re.findall(r"<script>(.*?)</script>", page, re.S)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    return script, f"script-src 'sha256-{digest}';" in page


CHIP = re.compile(r'<span class="chip agent">([^<]*) · <b>([\d,]+)</b> sessions?</span>')
TITLE = ("<h1>What your coding agents did</h1>", '<div class="what">Agent activity assessment</div>',
         "Your agents acted on your systems, and some of what they ran was risky.")


class Report(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.claude, _, _ = support.collect("sessions")
        cls.codex, _, _ = support.collect("codex")
        cls.pages = {name: report_of(*files) for name, files in (
            ("claude", (cls.claude,)), ("codex", (cls.codex,)), ("mixed", (cls.claude, cls.codex)))}

    def test_generic_title_in_every_report(self):
        for name, (page, _, _) in self.pages.items():
            for text in TITLE:
                self.assertIn(text, unescape(page), name)

    def test_one_chip_per_agent(self):
        chips = {name: CHIP.findall(unescape(page)) for name, (page, _, _) in self.pages.items()}
        self.assertEqual(chips, {"claude": [("Claude Code", "2")], "codex": [("Codex", "3")],
                                 "mixed": [("Claude Code", "2"), ("Codex", "3")]})

    def test_claude_only_never_says_codex(self):
        page, facts, _ = self.pages["claude"]
        self.assertNotIn("codex", page.lower())
        self.assertIn("Claude Code's permission rules and hooks see each command.", unescape(page))
        self.assertEqual(facts["sessions_by_agent"], {"claude-code": 2})

    def test_codex_only_never_says_claude_code(self):
        page, _, _ = self.pages["codex"]
        self.assertNotIn("Claude Code", unescape(page))
        self.assertIn("Codex's approval rules see each command.", unescape(page))

    def test_mixed(self):
        page, facts, digest = self.pages["mixed"]
        self.assertIn("Claude Code's permission rules and hooks, and Codex's approval rules, see each command.",
                      unescape(page))
        self.assertEqual(facts["sessions_by_agent"], {"claude-code": 2, "codex": 3})
        self.assertIn("sessions by agent: Claude Code 2 · Codex 3", digest)
        self.assertIn("claude_code_version", [r for r in facts["session_records"] if "agent" not in r][0])
        # Both agents' actions in one table.
        self.assertEqual(facts["findings"]["own:force-push:default-branch"]["count"], 2)

    def test_sessions_name_their_agent(self):
        for name, agents, mixed in (("claude", ["Claude Code"], False), ("codex", ["Codex", "Codex"], False),
                                    ("mixed", ["Claude Code", "Codex", "Codex"], True)):
            block = json.loads(re.search(r'id="session-data">(.*?)</script>', self.pages[name][0], re.S).group(1))
            self.assertEqual(sorted(r["agent"] for r in block["records"].values()), agents, name)
            self.assertEqual(block["mixed"], mixed, name)
            self.assertFalse({"codex_version", "claude_code_version"} & {k for r in block["records"].values() for k in r})

    def test_one_script_and_hash_for_every_report(self):
        scripts = set()
        for name, (page, _, _) in self.pages.items():
            script, pinned = script_of(page)
            self.assertTrue(pinned, name)
            self.assertNotIn("<!--", script)
            scripts.add(script)
        self.assertEqual(len(scripts), 1)
        self.assertIn('r.agent + " session on "', scripts.pop())

    def test_older_files_still_read(self):
        old = json.loads(json.dumps(self.claude))
        old["collector"]["version"] = "0.13.0"
        old.pop("sessions")
        page, facts, _ = report_of(old, self.codex)
        self.assertEqual(facts["endpoints"], ["host-a", "host-b"])
        self.assertEqual(facts["files_skipped"], [])
        self.assertEqual(CHIP.findall(unescape(page)), [("Claude Code", "2"), ("Codex", "3")])

    def test_bad_codex_fields(self):
        bad_record = json.loads(json.dumps(self.codex))
        bad_record["sessions"][0].pop("codex_version")
        _, facts, _ = report_of(bad_record)
        self.assertEqual(len(facts["session_records"]), 1)
        bad_users = json.loads(json.dumps(self.codex))
        bad_users["users"][0]["sessions_by_agent"] = {"codex": 99}
        bad_format = json.loads(json.dumps(self.codex))
        bad_format["format"]["codex"]["entries"] = "many"
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in (("a.json", bad_users), ("b.json", bad_format), ("c.json", self.claude)):
                (pathlib.Path(tmp) / name).write_text(json.dumps(data), encoding="utf-8")
            digest = support.run(support.REPORT, tmp, "--out", pathlib.Path(tmp) / "r.html")
        self.assertIn('"a.json" (bad users); "b.json" (bad format)', digest)

    def test_markup_in_a_codex_command_is_escaped(self):
        data = json.loads(json.dumps(self.codex))
        data["sessions"][0]["findings"][0]["examples"] = ["<img src=x onerror=alert(1)></script>"]
        data["findings"][0]["examples"] = ["<img src=x onerror=alert(1)>"]
        page, _, _ = report_of(data, self.claude)
        self.assertNotIn("<img", page)
        self.assertEqual(len(re.findall(r"<script>", page)), 1)


if __name__ == "__main__":
    unittest.main()
