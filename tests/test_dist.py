"""agent-activity.py: built from the sources, the same output, and what
it does when run with no options."""

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import support
import collect

BUILT = support.BUILT


def without_time(text):
    data = json.loads(text)
    data["endpoint"].pop("collected_at", None)
    # Session ids are salted afresh on each run; number them instead.
    for i, r in enumerate(data.get("sessions", [])):
        r["id"] = f"s_{i:012x}"
    return data


# macOS's own python3 where it exists, else the Python running the tests (Linux images have no /usr/bin/python3).
SYSTEM_PYTHON = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


class Python39(unittest.TestCase):

    def test_no_fstring_nests_its_own_quote(self):
        # macOS's own Python 3.9 can't read an f-string holding its own quote (allowed from 3.12).
        import io
        import tokenize
        if not hasattr(tokenize, "FSTRING_START"):
            self.skipTest("needs Python 3.12 to see f-string tokens")
        for name in ("collect.py", "report.py"):
            text = (support.SOURCE / name).read_text(encoding="utf-8")
            stack, bad = [], []
            for t in tokenize.generate_tokens(io.StringIO(text).readline):
                if t.type == tokenize.FSTRING_START:
                    quote = t.string[-3:] if t.string[-3:] in ('"""', "\'\'\'") else t.string[-1]
                    if stack and quote == stack[-1]:
                        bad.append(t.start[0])
                    stack.append(quote)
                elif t.type == tokenize.FSTRING_END:
                    stack.pop()
                elif stack and t.type == tokenize.STRING and len(stack[-1]) == 1 and stack[-1] in t.string:
                    bad.append(t.start[0])
            self.assertEqual(bad, [], f"{name}: lines that Python 3.9 can't read")


class Built(unittest.TestCase):

    def test_is_built_from_the_sources(self):
        spec = importlib.util.spec_from_file_location("bundle", support.SOURCE / "bundle.py")
        bundle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bundle)
        self.assertEqual(bundle.build(), BUILT.read_text(encoding="utf-8"), "run source/bundle.py")
        self.assertLess(BUILT.stat().st_size, 2**20, "Intune takes scripts under 1 MB")

    def test_windows_launcher_is_released(self):
        # Windows CI runs it; here, that it runs the script beside it isolated and ships with it.
        launcher = (support.REPO / "agent-activity.ps1").read_text(encoding="utf-8")
        self.assertIn("-I $script @args", launcher)
        release = (support.REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("sha256sum agent-activity.py agent-activity.ps1 > SHA256SUMS", release)
        self.assertIn("agent-activity.py agent-activity.ps1 SHA256SUMS", release)

    def test_windows_launcher_trusts_only_python_administrators_control(self):
        # Windows CI runs it; here, that as SYSTEM or an administrator no Python is run before its folder is checked.
        launcher = (support.REPO / "agent-activity.ps1").read_text(encoding="utf-8")
        check = launcher[launcher.index("function Test-Python"):]
        self.assertLess(check.index("Test-AdminOnly $p"), check.index("& $exe"))
        self.assertIn("$launchers = if ($system) { @(Join-Path $env:SystemRoot 'py.exe') }", launcher)
        self.assertIn("if (-not $system) {\n    foreach ($c in @(Get-Command python.exe", launcher)
        self.assertIn("foreach ($py in @($launchers | Where-Object { $_ -notlike '*\\WindowsApps\\*' }))", launcher)
        self.assertIn("if ($line -match", launcher)

    def test_windows_launcher_checks_what_python_loads_and_the_script_folder(self):
        launcher = (support.REPO / "agent-activity.ps1").read_text(encoding="utf-8")
        check = launcher[launcher.index("function Test-Python"):launcher.index("& $exe")]
        for part in ("'DLLs'", "'Lib\\site-packages'", "-Filter '*.dll'", "-Filter '*.pth'"):
            self.assertIn(part, check)
        self.assertLess(launcher.index("Test-AdminOnly $PSScriptRoot"), launcher.index("function Test-Python"))
        self.assertIn("(Test-AdminOnly (Split-Path -Parent $py))", launcher)
        self.assertNotIn("$me.User.Value)", launcher)

    def test_same_output_as_the_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            for case in ("resources", "risky_aws", "detections"):
                home = support.copy_case(case, tmp)
                for tool, out in (([sys.executable, support.COLLECT], tmp / "src" / f"{case}.json"),
                                  ([*support.SHIPPED, BUILT], tmp / "built" / f"{case}.json")):
                    out.parent.mkdir(exist_ok=True)
                    subprocess.run([*tool, "--home", home, "--days", str(support.days()), "--out", out],
                                   check=True, capture_output=True)
                src, built = (without_time((tmp / f / f"{case}.json").read_text(encoding="utf-8")) for f in ("src", "built"))
                self.assertEqual(src, built, case)
                # A distinct machine per file and one collection time, so the two reports can match.
                for folder, data in (("src", src), ("built", built)):
                    data["endpoint"].update(machine_id=case, collected_at="2026-10-26T00:00:00Z")
                    (tmp / folder / f"{case}.json").write_text(json.dumps(data))
            for folder, tool in (("src", [sys.executable, support.REPORT]), ("built", [*support.SHIPPED, BUILT, "report"])):
                subprocess.run([*tool, tmp / folder, "--org", "Acme"], check=True, capture_output=True)
            for name in ("agent-activity-report.html", "agent-activity-report.facts.json"):
                self.assertEqual((tmp / "src" / name).read_text(encoding="utf-8"),
                                 (tmp / "built" / name).read_text(encoding="utf-8"), name)

    def test_default_output(self):
        # In agent-activity-files next to the file, where `report` looks by default; in the
        # home folder when that folder can't be written; named by the machine. An administrator
        # on Windows is taken for an MDM: in %ProgramData%\AgentActivity, with nothing to send.
        admin = support.WINDOWS and collect.privileged()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp).resolve()
            logs = support.copy_case("benign", tmp)
            data = tmp / "ProgramData"
            data.mkdir()
            # Windows keeps who may write in ACLs: a read-only mode doesn't stop it.
            for writable in (True,) if support.WINDOWS else (True, False):
                home, here = pathlib.Path(tmp) / f"user-{writable}", pathlib.Path(tmp) / f"dl-{writable}"
                home.mkdir()
                here.mkdir()
                shutil.copy(BUILT, here / "agent-activity.py")
                if not writable:
                    here.chmod(0o555)
                done = subprocess.run([SYSTEM_PYTHON, here / "agent-activity.py", "--home", logs,
                                       "--name", "Asset 7", "--days", str(support.days())],
                                      capture_output=True, text=True,
                                      env=dict(os.environ, HOME=str(home), ProgramData=str(data)))
                out = (data / "AgentActivity" if admin else here / "agent-activity-files" if writable else home) \
                    / "agent-activity-Asset_7.json"
                self.assertEqual(done.stdout.splitlines(), [
                    f"Read the Claude Code logs of 1 user: 17 agent commands in the last {support.days()} days.",
                    f"Saved {out}"] + ([] if admin else ["Send this file to your security team."]), done.stderr)
                self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["endpoint"]["name"], "Asset_7")
                here.chmod(0o755)
            files = data / "AgentActivity" if admin else tmp / "dl-True" / "agent-activity-files"
            report = subprocess.run([*support.SHIPPED, tmp / "dl-True" / "agent-activity.py", "report"]
                                    + ([files] if admin else []), capture_output=True, text=True)
            self.assertTrue((files / "agent-activity-report.html").exists(), report.stderr)

    def test_root_folder_and_name(self):
        self.assertEqual(collect.default_folder(True, "Darwin", "/var/root"), "/Library/Application Support/AgentActivity")
        self.assertEqual(collect.default_folder(True, "Linux", "/root"), "/var/lib/agent-activity")
        self.assertEqual(collect.default_name("C02XK1ABCD", "a1b2c3d4e5f60718", "dana-mbp.local"), "C02XK1ABCD")
        self.assertEqual(collect.default_name("To Be Filled By O.E.M.", "a1b2c3d4e5f60718", "box"), "a1b2c3d4e5f6")
        self.assertEqual(collect.default_name("", "", "box.corp.example"), collect.host_hash("box.corp.example")[2:14])
        self.assertNotIn("box", collect.default_name("", "", "box.corp.example"))

    def test_upload_request(self):
        azure = collect.upload_request("https://acct.blob.core.windows.net/c/{name}.json?sv=1&sig=x", "C02 X/1", b"{}")
        self.assertEqual((azure.get_method(), azure.full_url, azure.data),
                         ("PUT", "https://acct.blob.core.windows.net/c/C02%20X%2F1.json?sv=1&sig=x", b"{}"))
        self.assertEqual(azure.get_header("X-ms-blob-type"), "BlockBlob")
        s3 = collect.upload_request("https://b.s3.amazonaws.com/k.json?X-Amz-Signature=x", "n", b"{}")
        self.assertEqual(dict(s3.header_items()), {"Content-type": "application/json"})
        for link in ("http://b.s3.amazonaws.com/k.json", "ftp://x/y", "https:///nohost"):
            with self.assertRaises(ValueError):
                collect.upload_request(link, "n", b"{}")
        # Jamf: `/ <computer> <user>` and parameter 4; then the link pasted in the file.
        self.assertEqual(collect.arguments(["/", "mac", "dana", "https://x/{name}"], "")[1], "https://x/{name}")
        self.assertEqual(collect.arguments(["/", "mac", "dana", ""], "https://pasted/")[1], "https://pasted/")
        self.assertEqual(collect.arguments(["--upload", "https://given/"], "https://pasted/")[1], "https://given/")

    def test_failed_upload_keeps_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = support.copy_case("benign", tmp)
            out = pathlib.Path(tmp) / "out.json"
            # Nothing listens on port 9 here, so the connection is refused at once.
            done = subprocess.run([sys.executable, support.COLLECT, "--home", logs, "--out", out,
                                   "--upload", "https://127.0.0.1:9/{name}.json"], capture_output=True, text=True)
            self.assertEqual(done.returncode, 1)
            self.assertTrue(out.is_file())
            self.assertIn(f"the file is still at {out}.", done.stderr)

    def test_expected_problems_are_one_sentence(self):
        for args in (["--home", "/nonexistent/home"], ["--upload", "http://example.com/x"]):
            done = subprocess.run([sys.executable, support.COLLECT, *args, "--out", "-"], capture_output=True, text=True)
            self.assertEqual((done.returncode, len(done.stderr.splitlines())), (2, 1), done.stderr)


if __name__ == "__main__":
    unittest.main()
