"""Runs the collector on a fixture.

Each fixture is a home folder under tests/fixtures/<case>/home. It is copied
to a temporary folder first, where `@ROOT@` in the session logs becomes the
copy's path, `@GHP@`, `@AWS_KEY@`, `@AWS_SECRET@` and `@AWS_SESSION@` fake
credentials in any file (assembled here from pieces, so secret scanners find
none in the repository) and `_git` becomes `.git` (git can't hold a .git).
"""

import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
SOURCE = REPO / "source"
COLLECT = SOURCE / "collect.py"
REPORT = SOURCE / "report.py"
BUILT = REPO / "agent-activity.py"
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(SOURCE))
GHP = "ghp_" + "Ab3dEf6hIj9lMn2pQr5tUv8xYz1bCd4fGh7j"
# AWS's documented example keys, which scanners still flag.
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/" + "K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
AWS_SESSION = "FwoGZXIvYXdz" + "EXAMPLESESSIONTOKEN"
FAKES = {"@GHP@": GHP, "@AWS_KEY@": AWS_KEY, "@AWS_SECRET@": AWS_SECRET, "@AWS_SESSION@": AWS_SESSION}
# Fixture sessions are from 2026-10-20 on; the window starts 2026-10-01
# whenever the tests run, so older entries stay outside it.
WINDOW_START = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
WINDOWS = os.name == "nt"
UID = os.getuid() if hasattr(os, "getuid") else -1
# The built script as shipped: `sh agent-activity.py` where there is a sh, else Python.
SHIPPED = [sys.executable] if WINDOWS else ["sh"]


def can_link():
    """Whether this account may make symbolic links (on Windows, an administrator or Developer Mode)."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.symlink(tmp, os.path.join(tmp, "link"))
        except OSError:
            return False
    return True


SYMLINKS = can_link()


def days():
    return (datetime.datetime.now(datetime.timezone.utc) - WINDOW_START).days + 1


def copy_case(case, into):
    """The fixture's home folder, copied into `into`."""
    root = pathlib.Path(into) / case
    shutil.copytree(FIXTURES / case, root)
    for path in sorted(root.rglob("_git"), key=lambda p: -len(p.parts)):
        path.rename(path.with_name(".git"))
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        text = original = path.read_text(encoding="utf-8")
        if path.suffix == ".jsonl":
            # Once more escaped in a JSON string held in one (a Codex call's arguments).
            text = text.replace('\\"@ROOT@', '\\"' + json.dumps(json.dumps(str(root))[1:-1])[1:-1])
            text = text.replace("@ROOT@", json.dumps(str(root))[1:-1])
        for placeholder, value in FAKES.items():
            text = text.replace(placeholder, value)
        if text != original:
            path.write_text(text, encoding="utf-8")
    return root / "home"


def run(*args, home=None):
    """Run a script; a `home` given as HOME must not change what the collector finds."""
    env = dict(os.environ, HOME=str(home)) if home else None
    done = subprocess.run([sys.executable] + [str(a) for a in args], capture_output=True, text=True,
                          encoding="utf-8", env=env)
    if done.returncode:
        raise AssertionError(f"{args[0]} failed:\n{done.stderr}")
    return done.stdout


def collect(case, before_run=None):
    """(output as parsed JSON, output text, home) for one fixture."""
    with tempfile.TemporaryDirectory() as tmp:
        home = copy_case(case, tmp)
        if before_run:
            before_run(home)
        out = pathlib.Path(tmp) / "out.json"
        decoy = pathlib.Path(tmp) / "collector-home"
        decoy.mkdir()
        run(COLLECT, "--home", home, "--days", days(), "--out", out, home=decoy)
        text = out.read_text(encoding="utf-8")
        return json.loads(text), text, str(home)


def findings(data):
    """(source, id) -> count."""
    return {(f["source"], f["id"]): f["count"] for f in data["findings"]}


def examples(data):
    return {(f["source"], f["id"]): f["examples"][0] for f in data["findings"]}


def resources(data, kind, *fields):
    """name -> (fields...) for one kind of resource."""
    return {e["name"]: tuple(e.get(f) for f in fields) for e in data["resources"][kind]}


def set_mtime(path, when):
    stamp = when.timestamp()
    os.utime(path, (stamp, stamp))
