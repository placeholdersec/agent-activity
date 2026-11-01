"""report.py on endpoint files made by the collector, and on hand-made ones."""

import base64
import hashlib
import json
import pathlib
import re
from html import unescape
import subprocess
import sys
import tempfile
import unittest

import support


class Sessions(unittest.TestCase):

    def test_records_merged_and_indexed_by_action(self):
        data, _, _ = support.collect("sessions")
        old = json.loads(json.dumps(data))
        old.pop("sessions")  # a file from a collector that doesn't write sessions
        bad = json.loads(json.dumps(data))
        bad["sessions"].append({"id": "../../etc", "started": 1})
        with tempfile.TemporaryDirectory() as tmp:
            for host, d in (("host-a", data), ("host-b", old), ("host-c", bad)):
                d["endpoint"] = dict(d["endpoint"], hostname=host, name=host, machine_id=host)
                (pathlib.Path(tmp) / f"{host}.json").write_text(json.dumps(d), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            support.run(support.REPORT, tmp, "--out", html, "--org", "Acme")
            facts = json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8"))
        records = facts["session_records"]
        # host-a's record, and host-c's good one; host-c's bad one is left out, not the file.
        self.assertEqual(sorted(r["machine"] for r in records), ["host-a", "host-c"])
        self.assertTrue(all(set(r) == {"id", "machine", "started", "ended", "claude_code_version", "project",
                                       "counts", "findings", "changes", "other_code"} for r in records))
        push = facts["findings"]["own:force-push:default-branch"]
        # Both machines' files are copies here, so they share the one session id.
        self.assertEqual(push["sessions"], sorted({r["id"] for r in records}))
        self.assertNotIn("dev-", json.dumps(records))


class Merge(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        aws, _, _ = support.collect("risky_aws")
        res, _, _ = support.collect("resources")
        files = {"host-a": dict(aws), "host-b": json.loads(json.dumps(aws)), "host-c": res}
        for host, data in files.items():
            data["endpoint"] = dict(data["endpoint"], hostname=host, name=host, machine_id=host)
        cls.files = files
        with tempfile.TemporaryDirectory() as tmp:
            for host, data in files.items():
                (pathlib.Path(tmp) / f"{host}.json").write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            cls.digest = support.run(support.REPORT, tmp, "--out", html, "--org", "Acme")
            cls.html = html.read_text(encoding="utf-8")
            facts = html.with_name("report.facts.json")
            cls.facts_exists = facts.is_file()
            cls.facts = json.loads(facts.read_text(encoding="utf-8"))

    def test_totals_add_up(self):
        for key in ("shell_commands", "findings", "mcp_calls", "web_fetches"):
            self.assertEqual(self.facts["totals"][key], sum(f["totals"][key] for f in self.files.values()), key)
        self.assertEqual(self.facts["commands"], sum(f["executed_other_code"]["of"] for f in self.files.values()))
        self.assertEqual(self.facts["endpoints"], ["host-a", "host-b", "host-c"])

    def test_findings_by_endpoint(self):
        bucket = self.facts["findings"]["traildiscover:DeleteBucket"]
        self.assertEqual((bucket["count"], bucket["endpoints"]), (3, ["host-a", "host-b", "host-c"]))
        stop = self.facts["findings"]["traildiscover:StopLogging"]
        self.assertEqual((stop["count"], stop["endpoints"]), (2, ["host-a", "host-b"]))
        for host in ("host-a", "host-b", "host-c"):
            self.assertIn(f'<span class="chip">{host}</span>', self.html)
        self.assertEqual(bucket["times_by_endpoint"], {"host-a": 1, "host-b": 1, "host-c": 1})
        # Each action says how often and on how many machines.
        self.assertIn('<td class="num">2<div class="muted">2 machines</div></td>', self.html)
        self.assertIn("endpoints 3", self.digest)

    def test_examples(self):
        import report
        # The same command on two machines is one example.
        self.assertEqual(self.facts["findings"]["traildiscover:DeleteBucket"]["examples"],
                         ["aws s3 rb s3://old-bucket --force", "aws s3 rb s3://old --profile staging"])
        self.assertIn('<div class="ex"><code>aws s3 rb s3://old-bucket --force</code>'
                      '<code>aws s3 rb s3://old --profile staging</code></div>', self.html)

    def test_sigma_findings_name_their_authors(self):
        # The Detection Rule License asks that each finding of a rule name its authors.
        import report
        self.assertEqual(report.label({"source": "sigma", "id": "proc_creation_lnx_userdel", "what": ""}),
                         "User has been deleted via userdel")

    def test_resources_merge(self):
        unknown = self.facts["resources"]["aws"]["unknown"]
        self.assertEqual((unknown["reads"], unknown["changes"]), (4 + 4 + 1, 6 + 6 + 0))
        self.assertEqual(self.facts["resources"]["mcp"]["linear"]["calls"], 3)

    def test_page_is_filled(self):
        self.assertTrue(self.facts_exists)
        self.assertNotIn("{{", self.html)
        self.assertIn("Acme", self.html)
        self.assertRegex(self.html, r"from files collected \d{4}-\d\d-\d\d\.</footer>")

    def test_format_in_facts_only(self):
        fmt = self.facts["format"]
        self.assertEqual(fmt["entries"], sum(f["format"]["entries"] for f in self.files.values()))
        self.assertEqual(fmt["unparsed_entries"], 0)
        self.assertEqual(fmt["claude_code_versions"], {"2.1.300": fmt["entries"]})
        self.assertEqual(fmt["tool_uses"], {"Bash": 11 + 11 + 33, "WebFetch": 2, "mcp": 4})
        self.assertNotIn("claude_code_versions", self.html)
        self.assertNotIn("2.1.300", self.html)



class LocalOnly(unittest.TestCase):

    def test_local_actions(self):
        data, _, _ = support.collect("detections")
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "host-a.json").write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            digest = support.run(support.REPORT, tmp, "--out", html)
            page = html.read_text(encoding="utf-8")
        # A hook skipped on the laptop never reaches the network.
        self.assertIn('"Git hooks skipped" · Defense Evasion · low · 1 · 1 · 1 · 1 · local', digest)
        self.assertNotIn("{{", page)


    def test_local_only_sets_no_group(self):
        plain = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
        plain["findings"] = [{"source": "own", "id": "local-history-discarded", "tactic": "Impact", "severity": "medium",
                              "local": True, "local_only": True, "what": "local-history-discarded", "count": 3,
                              "users": ["dev"], "examples": ["git reset --hard"]}]
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "a.json").write_text(json.dumps(plain), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            support.run(support.REPORT, tmp, "--out", html)
            page = unescape(html.read_text(encoding="utf-8"))
            facts = json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8"))
        self.assertEqual(list(facts["local_only"]), ["own:local-history-discarded"])
        self.assertEqual(facts["findings"], {})
        self.assertEqual({x["risky_actions"] for x in facts["groups"]["endpoints"].values()}, {"None"})
        self.assertIn("3 that only touched the machine\u2019s own copy of the code", page)
        self.assertIn("Only on the developer\u2019s own machine", page)
        self.assertIn("No high- or medium-risk action.", page)


class Show(unittest.TestCase):
    def test_opens_on_a_desktop_only(self):
        import report
        from unittest import mock
        cases = (("darwin", {}, ["/usr/bin/open", "r.html"]), ("linux", {"DISPLAY": ":0"}, ["xdg-open", "r.html"]),
                 ("linux", {}, None))
        for platform, env, expected in cases:
            with mock.patch.object(report.sys, "platform", platform), mock.patch.dict(report.os.environ, env, clear=True), \
                    mock.patch.object(report.subprocess, "run") as run:
                report.show("r.html")
            self.assertEqual(run.call_args[0][0] if run.called else None, expected, platform)


class SharedMachine(unittest.TestCase):
    def test_a_machine_collected_twice_counts_once_and_names_no_one(self):
        # One machine collected as root (two users), then as one user: the latest file is the machine.
        plain = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
        plain["endpoint"]["machine_id"] = "a1b2c3d4e5f60718"
        plain["users"] = [dict(plain["users"][0], name="ana-x1")]
        both = dict(plain, users=plain["users"] + [dict(plain["users"][0], name="sam-x2")])
        later = dict(plain, endpoint=dict(plain["endpoint"], collected_at="2026-10-21T09:00:00Z"))
        # Another machine of the same name and id, on another host, is told apart by its host name.
        twin = dict(plain, endpoint=dict(plain["endpoint"], hostname="build-01b"))
        # A home collected under a name of its own (--name) counts apart.
        named = dict(plain, endpoint=dict(plain["endpoint"], name="lab-2"))
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in (("a.json", both), ("b.json", later), ("c.json", twin), ("d.json", named)):
                (pathlib.Path(tmp) / name).write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            digest = support.run(support.REPORT, tmp, "--out", html)
            page = html.read_text(encoding="utf-8")
            facts_text = html.with_name("report.facts.json").read_text(encoding="utf-8")
        facts = json.loads(facts_text)
        self.assertIn('older duplicates, not counted: "a.json"', digest)
        self.assertEqual(facts["endpoints"], ["build-01 (build-01)", "build-01 (build-01b)", "lab-2"])
        for text in (page, facts_text, digest):
            self.assertNotIn("ana-x1", text)
            self.assertNotIn("sam-x2", text)

    def test_unreadable_folder_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            pathlib.Path(tmp).chmod(0)
            done = subprocess.run([sys.executable, support.REPORT, tmp], capture_output=True, text=True)
            pathlib.Path(tmp).chmod(0o700)
        self.assertIn("Can't read", done.stderr)


class Plain(unittest.TestCase):
    """An endpoint with no cloud, no GitHub and no findings, next to an older
    file from the same endpoint and two files that aren't endpoint files."""

    def test_names_only_what_the_data_has(self):
        plain = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
        older = dict(plain, endpoint=dict(plain["endpoint"], collected_at="2026-10-01T09:00:00Z"))
        bad = dict(plain, findings=[{"source": "own", "id": "x", "tactic": "Impact", "severity": "critical"}])
        old = dict(plain, collector={"rules": []})
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in (("a.json", plain), ("b.json", older), ("c.json", bad), ("d.json", [1, 2]), ("e.json", old)):
                (pathlib.Path(tmp) / name).write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            digest = support.run(support.REPORT, tmp, "--out", html)
            page = unescape(html.read_text(encoding="utf-8"))
            facts = json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8"))
        for word in ("{{", "AWS", "GitHub"):
            self.assertNotIn(word, page)
        self.assertIn("Started other code: 6 commands", page)
        self.assertIn("<li>1 log file couldn't be read.</li>", page)
        self.assertNotIn('<span class="pill warn" title=', page)
        self.assertIn("3 very large log entries, such as pasted images, were skipped. No commands were missed.",
                      page)
        self.assertEqual(facts["totals"]["shell_commands"], 40)  # the older file isn't counted twice
        self.assertIn('older duplicates, not counted: "b.json"', digest)
        self.assertIn('"c.json" (bad finding); "d.json" (not an endpoint file); '
                      '"e.json" (bad collector block)', digest)
        self.assertNotIn("dana", json.dumps(facts))

class Organisation(unittest.TestCase):
    """Three machines: a busy one, the plain one with few commands, and one
    whose logs are in a format the collector doesn't know."""

    def test_groups_scope_and_reach(self):
        plain = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
        days = {"first_activity": "2026-10-02", "last_activity": "2026-10-19"}
        busy = json.loads(json.dumps(plain))
        busy["endpoint"] = dict(busy["endpoint"], hostname="busy.corp.example", name="busy", **days)
        busy["executed_other_code"] = dict(busy["executed_other_code"], of=300)
        busy["resources"]["repositories"] = [{"name": f"acme/r{i}", "reads": 0, "changes": 1, "users": ["dana"]}
                                             for i in range(3)]
        # A prompt sent to an AI API is not a changed asset; a browser MCP server runs on the laptop.
        busy["resources"]["web"] = [{"name": "api.openai.com", "reads": 0, "changes": 5, "users": ["dana"]}]
        busy["resources"]["mcp"] = [{"name": "playwright", "reads": 0, "changes": 0, "calls": 9, "users": ["dana"],
                                     "tools": {"click": 9}},
                                    {"name": "linear", "reads": 1, "changes": 0, "calls": 1, "users": ["dana"],
                                     "tools": {"list_issues": 1}}]
        busy["errors"] = dict.fromkeys(busy["errors"], 0) | {"homes_skipped": 1}
        # A machine with no days of activity leaves the span to the others.
        odd = dict(plain, endpoint=dict(plain["endpoint"], hostname="odd", name="odd", first_activity="", last_activity=""),
                   format={"entries": 50, "unparsed_entries": 0, "claude_code_versions": {}, "tool_uses": {"run_shell": 50}})
        plain["endpoint"].update(days)
        with tempfile.TemporaryDirectory() as tmp:
            for data in (plain, busy, odd):
                (pathlib.Path(tmp) / f"{data['endpoint']['hostname']}.json").write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            digest = support.run(support.REPORT, tmp, "--out", html)
            page = unescape(html.read_text(encoding="utf-8"))
            facts = json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8"))
        # A machine with few commands is grouped like any other; a prompt to an AI API changes nothing.
        self.assertEqual(facts["groups"]["endpoints"]["busy"]["changed"], 3)
        self.assertEqual({n: (x["risky_actions"], x["changes"]) for n, x in facts["groups"]["endpoints"].items()},
                         dict.fromkeys(("build-01", "busy", "odd"), ("None", "Code & data")))
        self.assertIn("non-read actions on assets: 7 non-read actions on 4 assets; on 3 of 3 machines · in 3 of 9 sessions; "
                      "machines 0 Cloud & packages · 3 Code & data · 0 No changes", digest)
        self.assertIn("Agents on 3 of 3", page)
        self.assertIn("1 home folder and 2 log files couldn't be read. 1 machine's logs weren't in a "
                      "format the collector reads.", page)
        self.assertIn("2 Oct 2026 – 19 Oct 2026", page)


class Names(unittest.TestCase):

    def test_same_names_bad_dates_own_domains(self):
        # Two machines whose names and the first 8 characters of their ids match stay two;
        # a bad date is ignored; a host under a written repository's owner isn't Rare;
        # a report's own facts file isn't an endpoint file.
        plain = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            for host in ("macbook.local", "macbook.lan"):
                data = json.loads(json.dumps(plain))
                data["endpoint"].update(hostname=host, machine_id=host, name="macbook", first_activity="2026-13-01",
                                        last_activity="2026-13-02")
                data["resources"]["repositories"][0]["name"] = "acme-io/api"
                data["resources"]["web"] = [{"name": f"x{len(host)}.example", "reads": 0, "changes": 1, "users": ["dana"]}]
                (pathlib.Path(tmp) / f"{host}.json").write_text(json.dumps(data), encoding="utf-8")
            data["resources"]["web"].append({"name": "auth.acme.io", "reads": 0, "changes": 1, "users": ["dana"]})
            (pathlib.Path(tmp) / f"{host}.json").write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            support.run(support.REPORT, tmp, "--out", html)
            digest = support.run(support.REPORT, tmp, "--out", html)
            facts = json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8"))
        self.assertEqual(facts["endpoints"], ["macbook (macbook.lan)", "macbook (macbook.local)"])
        self.assertEqual(facts["rare_destinations"], 2)
        self.assertNotIn("skipped:", digest)


class Changes(unittest.TestCase):

    def test_every_change_shows(self):
        plain = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
        plain["executed_other_code"] = dict(plain["executed_other_code"], of=300)
        plain["resources"]["kubernetes"] = [{"name": n, "reads": 0, "changes": 2, "users": ["dana"]}
                                            for n in ("eks-prod-eu-1-admin", "staging", "product-ctx")]
        plain["resources"]["aws"] = [{"name": "111111111111", "reads": 100, "changes": 0, "users": ["dana"],
                                      "services": {"ec2": 100}, "profiles": []},
                                     {"name": "unknown", "reads": 0, "changes": 3, "users": ["dana"],
                                      "services": {"s3": 3}, "profiles": []}]
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "a.json").write_text(json.dumps(plain), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            support.run(support.REPORT, tmp, "--out", html)
            page = unescape(html.read_text(encoding="utf-8"))
            facts = json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8"))
        self.assertEqual(facts["groups"]["endpoints"]["build-01"]["changes"], "Cloud & packages")
        # A write in an account the logs don't name is counted and named as such.
        self.assertIn('<tr><td><span class="unn">Account not identifiable</span></td><td class="num">3</td></tr>', page)
        self.assertIn('AWS: 2 <tspan class="fl">· 1 written to</tspan>', page)
        self.assertIn('Kubernetes: 3 <tspan class="fl">· 3 written to</tspan>', page)
        # 3 clusters written to; the account only read is read only.
        self.assertIn('<tr><td><code>eks-prod-eu-1-admin</code></td><td class="num">2</td></tr>', page)
        self.assertIn('<p class="sgh">Read only: 1</p><div class="chips"><span class="chip acc">111111111111</span>', page)


class Page(unittest.TestCase):
    def test_script_order_and_lists(self):
        plain = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
        quiet = json.loads(json.dumps(plain))
        quiet["endpoint"] = dict(quiet["endpoint"], hostname="aaa", name="aaa", machine_id="aaa")
        busy = json.loads(json.dumps(plain))
        busy["endpoint"] = dict(busy["endpoint"], hostname="zzz", name="zzz", machine_id="zzz")
        busy["executed_other_code"] = dict(busy["executed_other_code"], of=300)
        busy["findings"] = [{"source": "own", "id": "force-push:default-branch", "tactic": "Impact", "severity": "high",
                             "local": False, "local_only": False, "what": "git push --force", "count": 1,
                             "users": ["dana"], "examples": ["git push --force origin main"]}]
        busy["resources"]["repositories"] = [{"name": f"acme/r{i:02}", "reads": 1, "changes": i % 2, "users": ["dana"]}
                                             for i in range(12)]
        # Data sent to a host on one machine that isn't a well-known service is rare; a read-only host comes last.
        busy["resources"]["web"] = [{"name": "docs.example.org", "reads": 3, "changes": 0, "users": ["dana"]},
                                    {"name": "paste.example.net", "reads": 0, "changes": 2, "users": ["dana"]},
                                    {"name": "gist.github.com", "reads": 0, "changes": 1, "users": ["dana"]},
                                    {"name": "api.github.com", "reads": 0, "changes": 5, "users": ["dana"]}]
        with tempfile.TemporaryDirectory() as tmp:
            for data in (quiet, busy):
                (pathlib.Path(tmp) / f"{data['endpoint']['hostname']}.json").write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            support.run(support.REPORT, tmp, "--out", html)
            page = html.read_text(encoding="utf-8")
            facts = json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8"))
        script = re.findall(r"<script>(.*?)</script>", page, re.S)
        self.assertEqual(len(script), 1)
        script_hash = base64.b64encode(hashlib.sha256(script[0].encode()).digest()).decode()
        self.assertIn(f"default-src 'none'; script-src 'sha256-{script_hash}';", page)
        # Every repository has a name in its panel, changed ones first with how many times.
        self.assertTrue(all(f"acme/r{i:02}<" in page for i in range(12)))
        self.assertLess(page.index('<code>acme/r11</code></td><td class="num">1<'), page.index('<span class="chip acc">acme/r00<'))
        self.assertEqual(facts["rare_destinations"], 2)
        self.assertNotIn(">Rare<", page)
        # Every row and branch that opens a panel has one.
        opened = set(re.findall(r'data-dw="([^"]+)"', page)) - {"sessions", "session"}
        self.assertEqual(opened - set(re.findall(r'<template id="dw-([^"]+)"', page)), set())
        # The way to learn more carries the two counts only.
        self.assertIn("learn-more?exec=12&amp;total=340", page)  # 6 + 6 of 40 + 300


class SessionsOnThePage(unittest.TestCase):

    def run_report(self, *flags, change=None):
        data, _, _ = support.collect("sessions")
        if change:
            change(data)
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "a.json").write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            support.run(support.REPORT, tmp, "--out", html, *flags)
            return html.read_text(encoding="utf-8")

    def test_session_data_is_never_run_and_names_no_one(self):
        page = self.run_report()
        block = re.search(r'<script type="application/json" id="session-data">(.*?)</script>', page, re.S).group(1)
        self.assertNotIn("</", block)
        data = json.loads(block)
        (record,) = data["records"].values()
        self.assertNotIn("claude_code_version", record)
        self.assertNotIn("user", json.dumps(data))
        self.assertEqual(data["by_finding"]["own:force-push:default-branch"], [record["id"]])
        self.assertIn('data-dw="sessions"', page)
        self.assertEqual(len(re.findall(r"<script>(.*?)</script>", page, re.S)), 1)

    def test_markup_in_a_logged_command_cannot_end_the_block(self):
        payload = "<!--<script></script><script>x</script>"
        def plant(data):
            data["sessions"][0]["findings"][0]["examples"] = [payload]
        page = self.run_report(change=plant)
        block = re.search(r'<script type="application/json" id="session-data">(.*?)</script>', page, re.S).group(1)
        self.assertNotIn("<", block)
        self.assertIn(payload, json.dumps(json.loads(block), ensure_ascii=False))
        self.assertEqual(len(re.findall(r"<script>(.*?)</script>", page, re.S)), 1)

    def test_left_out_when_asked(self):
        page = self.run_report("--no-sessions")
        self.assertNotIn('id="session-data"', page)
        self.assertNotIn('data-dw="sessions"', page)
        # Left out on purpose: no note that blames the collector.
        self.assertNotIn("Sessions show here when the files come from a newer collector.", page)


def plain_file(**changes):
    data = json.loads((support.FIXTURES / "merge" / "plain.json").read_text(encoding="utf-8"))
    data.update(changes)
    return data


def finding(severity="high", **more):
    return dict({"source": "own", "id": "force-push:default-branch", "tactic": "Impact", "severity": severity,
                 "local": False, "local_only": False, "what": "git push --force", "count": 10,
                 "users": ["dana"], "examples": ["git push --force origin main"]}, **more)


def record(i, *finding_ids, changes=()):
    return {"id": f"s_{i:012x}", "started": f"2026-10-1{i}T10:00:00Z", "ended": f"2026-10-1{i}T10:30:00Z",
            "claude_code_version": "2.1.300", "project": "acme/api",
            "counts": {"shell_commands": 5, "mcp_calls": 0, "web_fetches": 0, "tool_uses": {"Bash": 5}},
            "findings": [{"id": f, "at": f"2026-10-1{i}T10:01:00Z", "examples": ["x"]} for f in finding_ids],
            "changes": list(changes), "other_code": {"commands": 0, "by_kind": {}}}


def report_of(*files):
    """(page with entities decoded, facts, digest) for endpoint files given as dicts or raw text."""
    with tempfile.TemporaryDirectory() as tmp:
        for i, data in enumerate(files):
            text = data if isinstance(data, str) else json.dumps(data)
            (pathlib.Path(tmp) / f"f{i}.json").write_text(text, encoding="utf-8")
        html = pathlib.Path(tmp) / "report.html"
        digest = support.run(support.REPORT, tmp, "--out", html)
        return (unescape(html.read_text(encoding="utf-8")),
                json.loads(html.with_name("report.facts.json").read_text(encoding="utf-8")), digest)


class SessionBadges(unittest.TestCase):
    def test_local_only_actions_are_not_medium_or_high_in_sessions(self):
        local = finding("medium", id="local-history-discarded", local=True, local_only=True, count=1)
        data = plain_file(collector={"version": "0.15.0", "rules": []}, findings=[local],
                          sessions=[record(1, "own:local-history-discarded",
                                           changes=[{"kind": "repositories", "name": "acme/api", "count": 1}])])
        page, _, _ = report_of(data)
        self.assertIn("<b>0</b> ran or tried a medium- or high-risk one.", page)
        block = json.loads(re.search(r'id="session-data">(.*?)</script>', page, re.S).group(1))
        self.assertTrue(block["names"]["own:local-history-discarded"]["local_only"])
        self.assertIn("!nm.local_only", page)


class SystemSessions(unittest.TestCase):
    HOSTILE = 'acme/<img src=x onerror=alert(1)>"'

    def files(self):
        data = plain_file(collector={"version": "0.15.0", "rules": []})
        data["resources"].update(
            repositories=[{"name": "acme/api", "reads": 1, "changes": 3, "users": ["dana"]},
                          {"name": "acme/web", "reads": 0, "changes": 1, "users": ["dana"]},
                          {"name": "acme/docs", "reads": 4, "changes": 0, "users": ["dana"]},
                          {"name": self.HOSTILE, "reads": 0, "changes": 1, "users": ["dana"]}],
            registries=[{"name": "registry.npmjs.org", "reads": 0, "changes": 1, "users": ["dana"]}],
            aws=[{"name": "unknown", "reads": 0, "changes": 2, "users": ["dana"], "services": {"s3": 2},
                  "profiles": []}],
            web=[{"name": "api.openai.com", "reads": 0, "changes": 4, "users": ["dana"]}])
        change = lambda kind, name, n=1: {"kind": kind, "name": name, "count": n}
        data["sessions"] = [record(1, changes=[change("repositories", "acme/api", 2), change("aws", "unknown", 2)]),
                            record(2, changes=[change("repositories", "acme/api"), change("registries", "registry.npmjs.org"),
                                               change("repositories", self.HOSTILE)]),
                            record(3, changes=[change("web", "api.openai.com", 4), change("repositories", "acme/docs")])]
        return data

    def page(self, data, *flags):
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "a.json").write_text(json.dumps(data), encoding="utf-8")
            html = pathlib.Path(tmp) / "report.html"
            support.run(support.REPORT, tmp, "--out", html, *flags)
            return html.read_text(encoding="utf-8")

    def links(self, page):
        return {unescape(k): (unescape(label), int(n)) for k, label, n in re.findall(
            r'<span class="dwlink" data-dw="sessions" data-arg="([^"]*)" data-sys data-label="([^"]*)" '
            r'tabindex="0" role="button">(\d+) ›</span>', page)}

    def test_written_systems_open_their_sessions(self):
        page = self.page(self.files())
        block = json.loads(re.search(r'id="session-data">(.*?)</script>', page, re.S).group(1))
        ids = [record(i)["id"] for i in (1, 2, 3)]
        self.assertEqual(block["by_system"], {"repositories:acme/api": ids[:2], "aws:unknown": ids[:1],
                                              "registries:registry.npmjs.org": ids[1:2],
                                              "repositories:" + self.HOSTILE: ids[1:2]})
        links = self.links(page)
        self.assertEqual(links, {"repositories:acme/api": ("acme/api", 2),
                                 "aws:unknown": ("Account not identifiable", 1),
                                 "registries:registry.npmjs.org": ("registry.npmjs.org", 1),
                                 "repositories:" + self.HOSTILE: (self.HOSTILE, 1)})
        # Each opens from inside a system panel, kind and group alike, so Back returns to it.
        code = re.search(r'<template id="dw-(cat-\d+)" data-title="Code"[^>]*>(.*?)</template>', page, re.S).group(2)
        kind = re.search(r'<template id="dw-kind-repositories"[^>]*>(.*?)</template>', page, re.S).group(1)
        self.assertEqual(set(self.links(code)), set(links) - {"aws:unknown"})
        self.assertEqual(set(self.links(kind)), {"repositories:acme/api", "repositories:" + self.HOSTILE})
        # Written to outside any recorded session: no link. Read only, or an AI API prompt: no row to link.
        self.assertIn('<code>acme/web</code></td><td class="num">1</td><td class="ses"><span class="muted">–</span></td>', kind)
        self.assertIn('<span class="chip acc">acme/docs</span>', kind)
        self.assertIn('<span class="chip acc">api.openai.com</span>', page)
        self.assertIn("arg.system ? S.by_system : S.by_finding", page)
        self.assertIn('"sys" in t.dataset', page)

    def test_names_from_the_logs_are_escaped(self):
        page = self.page(self.files())
        self.assertNotIn("<img", page)
        self.assertIn('data-label="acme/&lt;img src=x onerror=alert(1)&gt;&quot;"', page)
        self.assertEqual(len(re.findall(r"<script>(.*?)</script>", page, re.S)), 1)

    def test_no_links_without_session_records(self):
        old = self.files()
        del old["sessions"]
        for page in (self.page(old), self.page(self.files(), "--no-sessions")):
            self.assertNotIn("data-sys", page.split("<script>")[0])
            self.assertNotIn('<td class="ses">', page)
            self.assertIn('<code>acme/api</code></td><td class="num">3</td></tr>', page)


class CommandBranches(unittest.TestCase):
    def test_two_branches_only(self):
        data = plain_file()
        data["executed_other_code"] = dict(data["executed_other_code"], visible_changes={"code": 3, "cloud": 0, "web": 1})
        page, facts, _ = report_of(data)
        section = re.search(r'id="guardrails".*?</section>', page, re.S).group(0)
        total, blind = data["executed_other_code"]["of"], data["executed_other_code"]["commands"]
        self.assertIn(f"Started other code: {blind:,} commands", section)
        self.assertIn(f"Everything else: {total - blind:,} commands", section)
        for name in ("Code repositories", "Cloud and Kubernetes", "Websites and APIs"):
            self.assertNotIn(name, section)
        self.assertEqual(facts["visible_changes"], {"code": 3, "cloud": 0, "web": 1})

    def test_older_files_have_no_visible_changes(self):
        new = plain_file()
        new["executed_other_code"] = dict(new["executed_other_code"], visible_changes={"code": 3, "cloud": 0, "web": 0})
        old = plain_file(endpoint=dict(new["endpoint"], hostname="old-01", name="old-01"))
        _, facts, _ = report_of(new, old)
        self.assertIsNone(facts["visible_changes"])

    def test_more_commands_than_ran_is_a_bad_file(self):
        bad = plain_file()
        bad["executed_other_code"] = dict(bad["executed_other_code"], visible_changes={"code": 40, "cloud": 0, "web": 0})
        _, _, digest = report_of(plain_file(endpoint=dict(bad["endpoint"], hostname="ok", name="ok")), bad)
        self.assertIn('"f1.json" (bad executed_other_code)', digest)


class Malformed(unittest.TestCase):
    def test_one_bad_file_skips_alone(self):
        good = plain_file()
        files = [good]
        for i, bad in enumerate(({"severity": ["high"]}, {"tactic": {"a": 1}}, {"session_count": 11})):
            files.append(plain_file(endpoint=dict(good["endpoint"], hostname=f"b{i}"), findings=[finding(**bad)]))
        files.append('{"schema": ' + "[" * 3000 + "]" * 3000 + "}")
        files.append(plain_file(endpoint=dict(good["endpoint"], hostname="deep"), extra=json.loads("[" * 200 + "]" * 200)))
        _, facts, digest = report_of(*files)
        self.assertEqual(facts["endpoints"], ["build-01"])
        for i in (1, 2, 3):
            self.assertIn(f'"f{i}.json" (bad finding)', digest)
        self.assertRegex(digest, r'"f4.json" \((nested too deep|not readable JSON)\)')
        self.assertIn('"f5.json" (nested too deep)', digest)

    def test_an_unforeseen_error_skips_the_file(self):
        import report
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "a.json").write_text(json.dumps(plain_file()), encoding="utf-8")
            with mock.patch.object(report, "problem", side_effect=KeyError("x")):
                files, skipped, _ = report.load(tmp)
        self.assertEqual((files, skipped), ([], [("a.json", "not a well-formed endpoint file")]))


class Conversation(unittest.TestCase):
    def test_comments_and_reviews_are_not_changes(self):
        data = plain_file()
        data["resources"]["repositories"] = [{"name": "acme/api", "reads": 0, "changes": 0, "conversation": 12,
                                              "users": ["dana"]},
                                             {"name": "acme/web", "reads": 1, "changes": 2, "conversation": 1,
                                              "users": ["dana"]}]
        old = plain_file(endpoint=dict(data["endpoint"], hostname="old-01", name="old-01"))
        old["resources"]["repositories"] = [{"name": "acme/old", "reads": 3, "changes": 0, "users": ["dana"]}]
        page, facts, digest = report_of(data, old)
        repos = facts["resources"]["repositories"]
        self.assertEqual((repos["acme/api"]["conversation"], repos["acme/api"]["changes"]), (12, 0))
        self.assertEqual(facts["changed_assets"], {"repositories": 1})
        self.assertEqual(repos["acme/old"]["conversation"], 0)
        self.assertIn('<span class="chip acc">acme/api · 12 comments or reviews</span>', page)
        self.assertIn('<code>acme/web</code><div class="muted">1 comment or review</div></td><td class="num">2<', page)
        self.assertIn('"acme/api" r0/c0/conversation12', digest)


class OncePerSession(unittest.TestCase):
    def test_counted_once_per_session_with_times_kept(self):
        data = plain_file(findings=[finding(session_count=2)])
        page, facts, digest = report_of(data)
        self.assertIn('<b>2</b><span class="t">risky actions agents ran or tried</span>', page)
        self.assertIn("counted once per session", page)
        self.assertIn('<a class="head" href="#risky">', page)
        self.assertIn('<td class="rb high"><span class="bb" style="width:100.0%"></span><b>2</b></td>', page)
        self.assertIn("10<small>times</small>", page)
        self.assertEqual({k: facts["risky_by_severity"]["high"][k] for k in ("times", "sessions")},
                         {"times": 10, "sessions": 2})
        self.assertIn("· high · 10 · 2 · 1 ·", digest)
        self.assertIn("risky actions: 2 high-risk actions, counted once per session", digest)

    def test_older_files_count_their_session_records_or_times(self):
        with_records = plain_file(collector={"version": "0.14.0", "rules": []},
                                  findings=[finding()], sessions=[record(1, "own:force-push:default-branch"),
                                                                  record(2, "own:force-push:default-branch")])
        _, facts, _ = report_of(with_records)
        self.assertEqual(facts["risky_by_severity"]["high"]["sessions"], 2)
        self.assertTrue(facts["risky_counted_once_per_session"])
        page, facts, _ = report_of(plain_file(findings=[finding()]))
        self.assertEqual(facts["risky_by_severity"]["high"]["sessions"], 10)
        self.assertFalse(facts["risky_counted_once_per_session"])
        self.assertNotIn("once per session", page)


class Plurals(unittest.TestCase):
    def test_one_is_singular(self):
        data = plain_file(findings=[finding(count=1, session_count=1)])
        data["users"][0] = dict(data["users"][0], sessions=1, sessions_by_group={
            "risky_actions": {"high": 1, "medium": 0, "none": 0},
            "changes": {"cloud_or_published": 0, "code_or_data": 1, "read_only": 0}})
        data["executed_other_code"] = {"commands": 1, "of": 1, "by_kind": {"scripts": 1}}
        page, _, _ = report_of(data)
        self.assertIn("Counted by session: 1 session<", page)
        self.assertIn('<tspan class="fl">· 1 written to</tspan>', page)
        self.assertIn('<span class="t">risky action agents ran or tried</span>', page)
        self.assertIn("agent command started other code", page)
        self.assertNotRegex(page, r">1 (sessions|repositories|commands|write operations|risky actions)\b")


class Versions(unittest.TestCase):
    def test_the_schema_decides_not_the_version(self):
        files = []
        for i, version in enumerate(("0.1.0", "0.13.0", "0.14.0", "0.15.0")):
            data = plain_file(collector={"version": version, "rules": []})
            data["endpoint"] = dict(data["endpoint"], hostname=f"h{i}", name=f"h{i}", machine_id=f"m{i}")
            files.append(data)
        files.append(dict(plain_file(), schema="agent-activity-endpoint/0"))
        files.append(dict(plain_file(), collector={"rules": []}))
        _, facts, _ = report_of(*files)
        self.assertEqual(facts["endpoints"], ["h0", "h1", "h2", "h3"])
        self.assertEqual(facts["files_skipped"], [{"file": "f4.json", "why": "not an endpoint file"},
                                                  {"file": "f5.json", "why": "bad collector block"}])


if __name__ == "__main__":
    unittest.main()
