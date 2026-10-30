#!/usr/bin/env python3
"""Build the collector's rule files from their open-source origins.

Run once, by hand, whenever the sources are refreshed. It reads local clones
of the sources (never runs anything from them) and writes compact JSON files
into rules/ next to this script, with each source's licence and a NOTICE
saying what was taken and changed. Needs PyYAML; the collector itself needs
only the standard library.

Usage: python3 source/build_rules.py <folder with the clones>

The clones are expected as:
  TrailDiscover/            adanalvarez/TrailDiscover           (CC-BY-4.0)
  panther-analysis/         panther-labs/panther-analysis       (Apache-2.0)
  pathfinding.cloud/        DataDog/pathfinding.cloud           (Apache-2.0)
  iam-dataset/              iann0036/iam-dataset                (MIT)
  claude-code-safety-net/   kenryu42/claude-code-safety-net     (MIT)
  shellfirm/                kaplanelad/shellfirm checks/*.yaml  (Apache-2.0)
  github-mcp-server/        github/github-mcp-server            (MIT)
  sigma/                    SigmaHQ/sigma                       (DRL 1.1)
  Detection-Rule-License/   SigmaHQ/Detection-Rule-License      (the DRL's text)
  codex/                    openai/codex at the commit in codex/commit.txt: its
                            is_safe_command.rs, LICENSE and NOTICE (Apache-2.0)
"""

import json
import pathlib
import re
import shutil
import subprocess
import sys

import yaml

SRC = pathlib.Path(sys.argv[1]).resolve()
OUT = pathlib.Path(__file__).resolve().parent / "rules"
OUT.mkdir(exist_ok=True)

TACTICS = {k: v["name"] for k, v in json.loads(
    next((SRC / "TrailDiscover/tools/attack").glob("enterprise-attack-*-lookup.json")).read_text())["tactics"].items()}

# Looking around, not doing: a call tagged only with these isn't a risky action.
QUIET_TACTICS = {"Discovery", "Reconnaissance", "Collection"}
# Tactics reported even for calls that only read.
READ_TACTICS = {"Credential Access", "Exfiltration"}

# CloudTrail data events: what agents do all day, too routine to flag. Deletes stay flagged.
DATA_EVENTS = {"S3": {"GetObject", "PutObject", "CopyObject", "HeadObject", "UploadPart", "UploadPartCopy",
                      "CreateMultipartUpload", "CompleteMultipartUpload", "RestoreObject", "SelectObjectContent",
                      "GetObjectAttributes", "ListObjects", "ListObjectsV2"},
               "Lambda": {"Invoke", "InvokeAsync", "InvokeWithResponseStream"}}

ACCESS = {"List": "L", "Read": "R", "Tagging": "T", "Write": "W", "Permissions management": "P"}
RANK = {"L": 0, "R": 1, "T": 2, "W": 3, "P": 4}


def commit(folder):
    try:
        return subprocess.run(["git", "-C", str(folder), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# AWS: every SDK method with its access level, and the risky ones flagged.
# ---------------------------------------------------------------------------

iam_map = json.loads((SRC / "iam-dataset/aws/map.json").read_text())
iam_def = json.loads((SRC / "iam-dataset/aws/iam_definition.json").read_text())

levels = {}  # "prefix:Action" -> access code
for service in iam_def:
    for privilege in service["privileges"]:
        levels[f"{service['prefix']}:{privilege['privilege']}"] = ACCESS.get(privilege["access_level"], "W")

methods = {}        # "Sdk.Method" -> access code
method_actions = {}  # "Sdk.Method" -> IAM actions
for method, mappings in iam_map["sdk_method_iam_mappings"].items():
    actions = [m["action"] for m in mappings if m.get("action")]
    codes = [levels.get(a) for a in actions if levels.get(a)]
    if codes:
        methods[method] = max(codes, key=RANK.get)
        method_actions[method] = actions

sdk_names = sorted({m.split(".", 1)[0] for m in methods})
by_prefix = {p: sorted(set(s) & set(sdk_names)) for p, s in iam_map["service_sdk_mappings"].items() if set(s) & set(sdk_names)}
norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())

ops_by_service = {}
for method in methods:
    service, op = method.split(".", 1)
    ops_by_service.setdefault(op, set()).add(service)

flags = {}  # "Sdk.Method" -> list of findings


def flag(method, finding):
    service, _, op = method.partition(".")
    if op in DATA_EVENTS.get(service, ()):
        return
    if method in methods:
        flags.setdefault(method, [])
        if finding not in flags[method]:
            flags[method].append(finding)


def reported(method, tactics):
    """Keep a flag only when the call changes something, or its tactic matters even for a read."""
    tactics = [t for t in tactics if t not in QUIET_TACTICS]
    if not tactics:
        return None
    if methods.get(method) in ("L", "R") and not set(tactics) & READ_TACTICS:
        return None
    return tactics


for path in sorted((SRC / "TrailDiscover/events").rglob("*.json")):
    event = json.loads(path.read_text())
    prefix = iam_map["cloudtrail_service_mappings"].get(event.get("eventSource", ""))
    tactics = [TACTICS.get(t.split(" - ")[0].strip(), t.split(" - ", 1)[-1]) for t in event.get("mitreAttackTactics", [])]
    for service in by_prefix.get(prefix, []):
        method = f"{service}.{event['eventName']}"
        kept = reported(method, tactics)
        if kept:
            flag(method, {"source": "traildiscover", "id": event["eventName"], "tactic": kept[0],
                          "severity": "high" if event.get("usedInWild") else "medium"})

# Panther rules flag calls by the event names in their code.
SEVERITY = {"Info": "low", "Low": "low", "Medium": "medium", "High": "high", "Critical": "high"}
for spec in sorted((SRC / "panther-analysis/rules/aws_cloudtrail_rules").glob("*.yml")):
    rule = yaml.safe_load(spec.read_text()) or {}
    code = spec.with_suffix(".py")
    if not rule.get("Enabled", True) or not code.exists():
        continue
    text = code.read_text()
    tactics = [TACTICS.get(t.split(":")[0]) for t in (rule.get("Reports") or {}).get("MITRE ATT&CK", [])]
    tactics = [t for t in tactics if t]
    sources = {iam_map["cloudtrail_service_mappings"].get(s) for s in re.findall(r'"([a-z0-9-]+\.amazonaws\.com)"', text)}
    services = sorted({sdk for p in sources if p for sdk in by_prefix.get(p, [])})
    if set(re.findall(r'"(Aws[A-Za-z]+(?:Event|SignIn))"', text)) - {"AwsApiCall"}:
        # Console sign-ins and VPC endpoint traffic aren't API calls an agent's command makes.
        continue
    names = sorted(set(re.findall(r'"([A-Z][A-Za-z0-9]{3,})"', text)))
    if len([n for n in names if n in ops_by_service]) > 25:
        # A catch-all rule would put one tactic on dozens of unrelated calls.
        continue
    for name in names:
        owners = ops_by_service.get(name, set())
        # The rule's own service when it names one; otherwise only names that
        # belong to a single service, so a common word can't land elsewhere.
        targets = [s for s in services if s in owners] if services else (sorted(owners) if len(owners) == 1 else [])
        for service in targets:
            method = f"{service}.{name}"
            kept = reported(method, tactics or ["Impact"])
            if kept:
                flag(method, {"source": "panther", "id": rule.get("RuleID", spec.stem), "tactic": kept[0],
                              "severity": SEVERITY.get(rule.get("Severity"), "medium")})

# pathfinding.cloud: privilege escalation in a single permission.
for path in sorted((SRC / "pathfinding.cloud/data/paths").rglob("*.y*ml")):
    entry = yaml.safe_load(path.read_text()) or {}
    required = [p.get("permission") for p in ((entry.get("permissions") or {}).get("required") or []) if p.get("permission")]
    if len(required) != 1:
        continue
    for method, actions in method_actions.items():
        if required[0] in actions:
            flag(method, {"source": "pathfinding.cloud", "id": entry.get("id", path.stem),
                          "tactic": "Privilege Escalation", "severity": "high"})

for method in flags:
    flags[method].sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["severity"]],
                                      ["pathfinding.cloud", "panther", "traildiscover"].index(f["source"]), f["id"]))

# Secret names and metadata are discovery; a secret's value is credential access.
AWS_OVERRIDES = {"SecretsManager.ListSecrets": ("medium", "Discovery"),
                 "SecretsManager.DescribeSecret": ("medium", "Discovery"),
                 "SSM.DescribeParameters": ("medium", "Discovery"),
                 "SecretsManager.BatchGetSecretValue": ("high", "Credential Access"),
                 # A disabled or deleted key makes what it encrypts unreadable.
                 "KMS.DisableKey": ("high", "Impact"), "KMS.ScheduleKeyDeletion": ("high", "Impact"),
                 # Runs commands on instances; escalating is what may follow.
                 "SSM.SendCommand": ("high", "Execution")}
for method, (severity, tactic) in AWS_OVERRIDES.items():
    flags[method] = [dict(f, severity=severity, tactic=tactic) for f in flags[method]]

(OUT / "aws.json").write_text(json.dumps({
    "sdk_by_norm": {norm(s): s for s in sdk_names},
    "sdk_by_prefix": by_prefix,
    "methods": methods,
    "flags": flags,
}, sort_keys=True, separators=(",", ":")) + "\n")
print(f"aws: {len(methods)} methods, {len(flags)} flagged")

# ---------------------------------------------------------------------------
# GitHub: gh commands mapped to the audit actions Panther alerts on.
# ---------------------------------------------------------------------------

S = r"[^|;&\n]*"
GH_COMMANDS = [
    # (audit action, pattern on one command part)
    ("repo.destroy", r"^gh\s+repo\s+delete\b"),
    ("repo.access", r"^gh\s+repo\s+(edit|create)\b" + S + r"(--visibility[ =]public|--public\b)"),
    ("repo.access", r"^gh\s+api\b" + S + r"visibility\W+public"),
    ("repo.archived", r"^gh\s+repo\s+archive\b"),
    ("protected_branch.destroy", r"^gh\s+api\b(?=" + S + r"(-X|--method)\s*DELETE)" + S + r"branches/\S+/protection"),
    ("repo.add_member", r"^gh\s+api\b(?=" + S + r"(-X|--method)\s*PUT)" + S + r"repos/\S+/collaborators/"),
    # An owner (role=admin), or a member of an owners or admins team, ahead of a plain member.
    ("org.update_member", r"^gh\s+api\b(?=" + S + r"(-X|--method)\s*PUT)(?=" + S
     + r"(\brole\W+(admin|owner)\b|orgs/[^/\s]+/teams/[^/\s]*(admin|owner)[^/\s]*/memberships/))" + S
     + r"orgs/\S+/memberships/"),
    ("org.add_member", r"^gh\s+api\b(?=" + S + r"(-X|--method)\s*PUT)" + S + r"orgs/\S+/memberships/"),
    ("public_key.create", r"^gh\s+(repo\s+deploy-key|ssh-key)\s+add\b"),
    ("hook.create", r"^gh\s+api\b(?=" + S + r"(-X|--method)\s*POST)" + S + r"(repos|orgs)/\S+/hooks\b"),
    ("repository_secret_scanning_push_protection.disable", r"^gh\s+api\b" + S + r"secret_scanning_push_protection\W+disabled"),
]
# Panther tags these Initial Access (T1195, supply chain); these fit what the command does.
GH_TACTICS = {"repo.add_member": "Persistence", "org.add_member": "Persistence",
              "protected_branch.destroy": "Defense Evasion"}
github = []
panther_gh = {}
for spec in sorted((SRC / "panther-analysis/rules/github_rules").glob("*.yml")):
    rule = yaml.safe_load(spec.read_text()) or {}
    code = spec.with_suffix(".py")
    if not rule.get("Enabled", True) or not code.exists():
        continue
    tactics = [TACTICS.get(t.split(":")[0]) for t in (rule.get("Reports") or {}).get("MITRE ATT&CK", [])]
    for action in set(re.findall(r'"([a-z_]+\.[a-z_]+)"', code.read_text())):
        panther_gh.setdefault(action, []).append((rule.get("RuleID", spec.stem), next((t for t in tactics if t), "Impact"),
                                                  SEVERITY.get(rule.get("Severity"), "medium")))
for action, pattern in GH_COMMANDS:
    for rule_id, tactic, severity in sorted(panther_gh.get(action, []))[:1]:
        github.append({"source": "panther", "id": rule_id, "action": action,
                       "tactic": GH_TACTICS.get(action, tactic),
                       "severity": severity, "pattern": pattern})
(OUT / "github.json").write_text(json.dumps(github, indent=1, sort_keys=True) + "\n")
print(f"github: {len(github)} of {len(GH_COMMANDS)} command kinds have a Panther rule:",
      sorted({g['action'] for g in github}))

# ---------------------------------------------------------------------------
# Secret files: claude-code-safety-net's list of files that hold secrets.
# ---------------------------------------------------------------------------

ts = (SRC / "claude-code-safety-net/src/core/rules/secret.ts").read_text()


def block(name):
    match = re.search(r"(?:export )?const " + name + r"\b[^=]*=\s*(\[.*?\n\]|\{.*?\n\})", ts, re.S)
    return match.group(1) if match else ""


quoted = lambda text: re.findall(r"'([^']*)'", text)
basenames = sorted(set(re.findall(r"basename:\s*'([^']+)'", block("SECRET_BASENAME_RULES"))))
home = [quoted(m) for m in re.findall(r"suffixParts:\s*\[([^\]]*)\]", block("SECRET_HOME_PATH_RULES"))]
variant_suffixes = quoted(block("SECRET_HOME_PATH_CONFIG_VARIANT_SUFFIXES"))
for directory, base in re.findall(r"directoryParts:\s*\[([^\]]*)\],\s*basename:\s*'([^']+)'",
                                  block("SECRET_HOME_PATH_CONFIG_VARIANT_BASES")):
    home += [quoted(directory) + [base + suffix] for suffix in variant_suffixes]
cli_paths = sorted(set(quoted(" ".join(re.findall(r"paths:\s*\[([^\]]*)\]", block("SECRET_CODING_CLI_RULES"), re.S)))))
prefixes = sorted(set(re.findall(r"prefix:\s*'([^']+)'", block("SECRET_VARIANT_PREFIXES"))))
dot_suffixes = quoted(block("SECRET_DOT_VARIANT_SUFFIXES"))
extensions = quoted(block("SECRET_EXTENSION_RULES"))
extension_patterns = re.findall(r"pattern:\s*/(.+?)/,", block("SECRET_EXTENSION_PATTERN_RULES"))
default_off = set(quoted(block("SECRET_DEFAULT_OFF_RULE_ID_SET")))
ssh_pattern = re.findall(r"pattern:\s*/(.+?)/,", block("SECRET_BROAD_SSH_KEY_BASENAME_RULE"))
(OUT / "secrets.json").write_text(json.dumps({
    "basenames": basenames,
    "home_paths": sorted({"/".join(parts) for parts in home if parts}),
    "coding_cli_paths": cli_paths,
    "variant_prefixes": prefixes,
    "variant_dot_suffixes": dot_suffixes,
    "extensions": sorted(set(extensions)),
    "extension_patterns": extension_patterns,
    "basename_patterns": [] if "secret.pattern.ssh-key-basename" in default_off else ssh_pattern,
    "env_variant": {"prefix": ".env.", "not_suffixes": [".example", ".sample", ".template", ".tpl"],
                    "not_prefixes": [".env.example.", ".env.sample."], "not_names": [".env.defaults"]},
}, indent=1, sort_keys=True) + "\n")
print(f"secrets: {len(basenames)} names, {len(home)} home paths, {len(cli_paths)} coding-CLI paths, "
      f"{len(extensions)} extensions")

# ---------------------------------------------------------------------------
# Shell: shellfirm's checks, Critical and High, for what reaches beyond this
# machine.
# ---------------------------------------------------------------------------

SKIP_PACKS = {"fs", "base", "network", "docker"}
GIT_KEEP = {"git:push_mirror", "git:push_delete_branch"}
# Left to collect.py's own rule, which ranks fetched code by its source.
DOWNLOAD_RUN = {"shell:curl_pipe_to_shell", "shell:wget_pipe_to_shell", "shell:eval_curl", "shell:curl_pipe_to_interpreter"}
TACTIC_BY_WORD = [  # the rule id decides the tactic; first match wins
    ("Exfiltration", r"visibility|public|publish|expose|acl"),
    ("Defense Evasion", r"log|trail|audit|monitor|protection"),
    ("Impact", r"force_push|push_mirror|filter_branch|reflog|delete|remove|destroy|drop|terminate|purge|truncate|wipe"
               r"|flush|prune|clean|discard|uninstall|rm\b|_rm|down\b|archive|rename|stop|kill|drain|scale"
               r"|update_all"),
    ("Privilege Escalation", r"iam|policy|permission|role|chmod|chown|access|grant"),
    ("Credential Access", r"secret|credential|token|password"),
]
# What a rule's pattern matches but isn't its action.
SHELL_UNLESS = {"github:repo_change_visibility": ["--visibility[ =][\"']?(private|internal)\\b"],
                # A process search names the command it looks for.
                "git:push_mirror": [r"^(pgrep|pkill|killall|ps)\s"],
                # SQL in a script's test strings isn't run against a database.
                "database:drop_table": [r"^(\w+=\S*\s+)*(python[\d.]*|pytest|node|deno|bun|ruby|php|conda|uv|poetry|pipenv)\b"]}
shell = []
for path in sorted((SRC / "shellfirm").glob("*.yaml")):
    if path.stem in SKIP_PACKS:
        continue
    for rule in yaml.safe_load(path.read_text()) or []:
        rid = rule["id"]
        if "-strict:" in rid or rule.get("severity") not in ("Critical", "High"):
            continue
        if (path.stem == "git" and rid not in GIT_KEEP) or rid in DOWNLOAD_RUN:
            continue
        try:
            re.compile(rule["test"])
        except re.error:
            continue
        tactic = next((t for t, p in TACTIC_BY_WORD if re.search(p, rid)), "Execution")
        shell.append({"source": "shellfirm", "id": rid, "tactic": tactic, "severity": "high", "pattern": rule["test"],
                      "not_contains": [f["value"] for f in rule.get("filters") or [] if f.get("type") == "NotContains"],
                      "unless": SHELL_UNLESS.get(rid, [])})
(OUT / "shell.json").write_text(json.dumps(shell, indent=1, sort_keys=True) + "\n")
print(f"shell: {len(shell)} rules")

# ---------------------------------------------------------------------------
# MCP tools: GitHub's from its server's own annotations, into the hand-kept
# mcp_tools.json.
# ---------------------------------------------------------------------------

mcp_path, snaps = OUT / "mcp_tools.json", SRC / "github-mcp-server/pkg/github/__toolsnaps__"
mcp = json.loads(mcp_path.read_text())
github_mcp = {"read": set(), "change": set()}
for path in sorted(snaps.glob("*.snap")):
    snap = json.loads(path.read_text())
    if "annotations" in snap:  # *_output.snap files hold none
        github_mcp["read" if snap["annotations"].get("readOnlyHint") else "change"].add(snap["name"])
row = next(r for r in mcp["servers"] if r["name"] == "GitHub")
row.update({mode: sorted(names) for mode, names in github_mcp.items()})
mcp_path.write_text(json.dumps(mcp, indent=1, ensure_ascii=False) + "\n")
print(f"mcp: {len(github_mcp['read'])} GitHub read tools, {len(github_mcp['change'])} change tools")

# ---------------------------------------------------------------------------
# Sigma: process-creation rules for Linux and macOS, as patterns on one
# command, and CloudTrail rules, as flags on the AWS calls they name.
# ---------------------------------------------------------------------------

SIGMA_URL = "https://github.com/SigmaHQ/sigma/blob/{commit}/{path}"
SIGMA_DIRS = ("rules", "rules-threat-hunting", "rules-emerging-threats")
# Sigma's low and informational levels are hunting leads, not actions to report.
SIGMA_SEVERITY = {"critical": "high", "high": "high", "medium": "medium"}
# ATT&CK v18 split Defense Evasion; the report keeps the one name.
SIGMA_TACTICS = {"stealth": "Defense Evasion", "defense-impairment": "Defense Evasion",
                 **{v.lower().replace(" ", "-"): v for v in TACTICS.values()}}
# Rules left out by the precision gate on public coding agents' logs (judged
# matches below 90% right), by file name...
SIGMA_DROPPED = {
    "proc_creation_lnx_susp_curl_fileupload",  # any POST with a body: API calls
    "proc_creation_lnx_python_http_server_execution", "proc_creation_macos_launchctl_execution",
    "proc_creation_lnx_susp_sensitive_file_access", "proc_creation_macos_creds_from_keychain",
    "proc_creation_macos_sysctl_discovery", "proc_creation_macos_change_file_time_attr",
    "proc_creation_macos_hdiutil_create", "proc_creation_lnx_mkfifo_named_pipe_creation_susp_location",
    "proc_creation_macos_system_profiler_discovery", "proc_creation_macos_binary_padding",
    "proc_creation_lnx_cp_passwd_or_shadow_tmp", "proc_creation_macos_chflags_hidden_flag",
    "proc_creation_macos_schedule_task_job_cron", "proc_creation_macos_susp_histfile_operations",
    "proc_creation_lnx_susp_process_termination_via_kill",
    # Terminal-Bench's benign tasks: tools installed or downloaded to /tmp.
    "proc_creation_lnx_install_suspicious_packages", "proc_creation_lnx_wget_download_suspicious_directory",
    # ...and those right but routine for agents, firing on more than 1 in
    # 1,000 of their commands: scratch programs run from /tmp.
    "proc_creation_lnx_susp_execution_tmp_folder"}
# Where each field's text may start in "<image>\t<command line>" (collect.sigma_rule).
SIGMA_FIELD = {"Image": r"[^\t]*?", "CommandLine": r"[^\t]*\t.*?"}


class NotConvertible(Exception):
    pass


def sigma_text(value):
    """A Sigma string as a regex: `*` and `?` are wildcards; case is ignored."""
    out, i = [], 0
    while i < len(value):
        if value[i] == "\\" and value[i + 1:i + 2] in ("*", "?", "\\"):
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append({"*": ".*?", "?": "."}.get(value[i]) or re.escape(value[i]))
        i += 1
    return "(?i:" + "".join(out) + ")"


def sigma_keys(value):
    """The longest plain run a match must hold, a cheap first test; None when too short."""
    run = max(re.split(r"(?<!\\)[*?]", value), key=len).replace("\\", "").lower()
    return {run} if len(run) >= 3 else None


def sigma_value(field, mods, value):
    """(lookahead, the image names it allows, the words it needs; None: any)
    for one value of a field."""
    if value is None or isinstance(value, (dict, list)):
        raise NotConvertible("value")
    value = str(value)
    start = "" if field == "Image" else r"[^\t]*\t"
    if "re" in mods:
        flags = re.match(r"^\(\?([imsx]+)\)", value)
        body = "(?%s:%s)" % (flags.group(1), value[flags.end():]) if flags else value
        re.compile(body)
        if body.startswith("^"):
            return "(?=" + start + body[1:] + ")", None, None
        return "(?=" + SIGMA_FIELD[field] + "(?:" + body + "))", None, None
    text, end, keys = sigma_text(value), r"\t" if field == "Image" else "$", sigma_keys(value)
    if "contains" in mods:
        return "(?=" + SIGMA_FIELD[field] + text + ")", None, keys
    if "startswith" in mods:
        return "(?=" + start + text + ")", None, keys
    name = None
    if field == "Image" and "/" in value and not re.search(r"[*?]", value):
        name = {value.rsplit("/", 1)[-1].lower()}
    if "endswith" in mods:
        return "(?=" + SIGMA_FIELD[field] + text + end + ")", name, keys
    return "(?=" + start + text + end + ")", name, keys


def sigma_and(items):
    names = [n for _, n, _ in items if n is not None]
    # Of the words each part needs, those of the part whose shortest is longest.
    keys = max((k for _, _, k in items if k), key=lambda k: min(map(len, k)), default=None)
    return "".join("(?:%s)" % r for r, _, _ in items), set.intersection(*names) if names else None, keys


def sigma_or(items):
    names, keys = [n for _, n, _ in items], [k for _, _, k in items]
    return ("(?:%s)" % "|".join(r for r, _, _ in items), None if None in names else set().union(*names),
            None if None in keys else set().union(*keys))


def sigma_selection(sel):
    """A map ANDs its fields, a list of maps ORs them."""
    if isinstance(sel, list) and all(isinstance(s, dict) for s in sel):
        return sigma_or([sigma_selection(s) for s in sel])
    if not isinstance(sel, dict):
        raise NotConvertible("keywords")
    parts = []
    for key, values in sel.items():
        field, *mods = key.split("|")
        if field not in SIGMA_FIELD or set(mods) - {"contains", "startswith", "endswith", "all", "re"}:
            raise NotConvertible(field)  # the parent process or the user: not in the logs
        alts = [sigma_value(field, mods, v) for v in (values if isinstance(values, list) else [values])]
        parts.append(sigma_and(alts) if "all" in mods else sigma_or(alts))
    return sigma_and(parts)


def sigma_condition(cond, detection):
    """A condition (and, or, not, brackets, `1 of x*`, `all of x*`) as one
    regex of lookaheads, with the image names and words it needs."""
    tokens = re.findall(r"\(|\)|(?:1|all) of [\w*]+|[\w*]+", cond)
    if "".join(tokens).replace(" ", "") != re.sub(r"\s+", "", cond):
        raise NotConvertible("condition")
    names, at = [k for k in detection if k != "condition"], [0]

    def peek():
        return tokens[at[0]] if at[0] < len(tokens) else None

    def take():
        at[0] += 1
        return tokens[at[0] - 1]

    def either():
        items = [both()]
        while peek() == "or":
            take()
            items.append(both())
        return items[0] if len(items) == 1 else sigma_or(items)

    def both():
        items = [negated()]
        while peek() == "and":
            take()
            items.append(negated())
        return items[0] if len(items) == 1 else sigma_and(items)

    def negated():
        if peek() == "not":
            take()
            return "(?!%s)" % negated()[0], None, None
        token = take()
        if token == "(":
            inner = either()
            if take() != ")":
                raise NotConvertible("brackets")
            return inner
        quantified = re.match(r"(1|all) of ([\w*]+)$", token)
        if quantified:
            glob = quantified.group(2)
            got = [sigma_selection(detection[n]) for n in names
                   if glob == "them" or re.match("^" + glob.replace("*", ".*") + "$", n)]
            if not got:
                raise NotConvertible("selection")
            return sigma_and(got) if quantified.group(1) == "all" else sigma_or(got)
        if token not in detection:
            raise NotConvertible("selection")
        return sigma_selection(detection[token])

    out = either()
    if peek() is not None:
        raise NotConvertible("condition")
    return out


def sigma_meta(rule, path):
    tactics = [SIGMA_TACTICS.get(t[len("attack."):]) for t in rule.get("tags") or []
               if t.startswith("attack.")]
    uri = SIGMA_URL.format(commit=commit(SRC / "sigma"), path=path.relative_to(SRC / "sigma").as_posix())
    return {"title": rule["title"], "author": " ".join(str(rule.get("author", "")).split()), "uri": uri,
            "tactics": [t for t in tactics if t and t not in QUIET_TACTICS]}


def sigma_skip(rule, path, meta):
    """Why a rule is left out, or None."""
    if rule.get("status") in ("deprecated", "unsupported") or path.stem in SIGMA_DROPPED:
        return "dropped"
    if rule.get("level") not in SIGMA_SEVERITY:
        return "level " + str(rule.get("level"))
    return None if meta["tactics"] else "discovery only"  # what agents run all day to look around


sigma_rules, sigma_process, sigma_skipped = {}, [], {}
for path in sorted(p for d in SIGMA_DIRS for p in (SRC / "sigma" / d).rglob("*.yml")):
    rule = yaml.safe_load(path.read_text()) or {}
    source = rule.get("logsource") or {}
    if source.get("category") != "process_creation" or source.get("product") not in ("linux", "macos"):
        continue
    meta = sigma_meta(rule, path)
    why = sigma_skip(rule, path, meta)
    if not why:
        try:
            conditions = rule["detection"]["condition"]
            conditions = conditions if isinstance(conditions, list) else [conditions]
            pattern, images, keys = sigma_or([sigma_condition(c, rule["detection"]) for c in conditions])
            re.compile(pattern, re.S)
        except (NotConvertible, re.error, KeyError) as e:
            why = "needs " + str(e)
    if why:
        sigma_skipped[why] = sigma_skipped.get(why, 0) + 1
        continue
    sigma_rules[path.stem] = meta
    sigma_process.append({"source": "sigma", "id": path.stem, "tactic": meta["tactics"][0],
                          "severity": SIGMA_SEVERITY[rule["level"]], "pattern": "^" + pattern,
                          "images": sorted(images) if images else None,
                          "keys": sorted(keys) if keys else None})

# CloudTrail rules flag the calls they name, by name alone as Panther's do,
# where no other source flags them.
sigma_aws = 0
for path in sorted((SRC / "sigma/rules/cloud/aws").rglob("*.yml")):
    rule = yaml.safe_load(path.read_text()) or {}
    meta = sigma_meta(rule, path)
    if sigma_skip(rule, path, dict(meta, tactics=["Impact"])):
        continue
    named = set()
    for selection in (v for k, v in rule["detection"].items() if k != "condition"):
        for m in selection if isinstance(selection, list) else [selection]:
            if isinstance(m, dict) and "eventName" in m:
                listed = lambda v: v if isinstance(v, list) else [v]  # noqa: E731
                sources = listed(m.get("eventSource"))
                prefixes = {iam_map["cloudtrail_service_mappings"].get(s) for s in sources}
                named |= {f"{s}.{e}" for p in prefixes for s in by_prefix.get(p, [])
                          for e in listed(m["eventName"])}
    for method in sorted(named):
        kept = reported(method, meta["tactics"] or ["Impact"])
        if kept and method in methods and method not in flags:
            flags[method] = [{"source": "sigma", "id": path.stem, "tactic": kept[0],
                              "severity": SIGMA_SEVERITY[rule["level"]]}]
            sigma_rules[path.stem] = meta
            sigma_aws += 1
if sigma_aws:
    aws_rules = json.loads((OUT / "aws.json").read_text())
    aws_rules["flags"] = flags
    (OUT / "aws.json").write_text(json.dumps(aws_rules, sort_keys=True, separators=(",", ":")) + "\n")


def trie_re(words):
    """A regex for any of the words, as a trie: far quicker than a list of them."""
    trie = {}
    for word in words:
        node = trie
        for c in word:
            node = node.setdefault(c, {})
        node[""] = {}

    def walk(node):
        alts = [re.escape(c) + walk(child) for c, child in sorted(node.items()) if c]
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return "(?:%s)?" % body if "" in node else body
    return walk(trie)


for meta in sigma_rules.values():
    del meta["tactics"]
# The words any rule for every program needs: a command with none of them
# skips those rules.
screen = trie_re({k for r in sigma_process if not r["images"] for k in r["keys"] or [""]})
(OUT / "sigma.json").write_text(json.dumps({"process": sigma_process, "rules": sigma_rules, "screen": screen},
                                           indent=1, sort_keys=True, ensure_ascii=False) + "\n")
print(f"sigma: {len(sigma_process)} process rules, {sigma_aws} AWS calls; left out: {sigma_skipped}")

# ---------------------------------------------------------------------------
# Known read-only commands: those Codex runs without asking, which can't
# change anything (they can print a secret file; collect.py checks that).
# ---------------------------------------------------------------------------

rs = (SRC / "codex/is_safe_command.rs").read_text()
arms = re.findall(r'Some\(([^()]*)\)\s*(?:=>|if)', rs) + re.findall(r'matches!\(cmd,([^)]*)\)', rs)
read_only = {"programs": sorted({p for arm in arms for p in re.findall(r'"([\w-]+)"', arm)} - {"git"}),
             "unsafe_options": {}}
for program, const in (("find", "UNSAFE_FIND_OPTIONS"), ("base64", "UNSAFE_BASE64_OPTIONS"),
                       ("rg", "UNSAFE_RIPGREP_OPTIONS_WITH_ARGS"),
                       ("rg", "UNSAFE_RIPGREP_OPTIONS_WITHOUT_ARGS")):
    listed = re.sub(r"//[^\n]*", "", re.search(const + r"[^=]*=\s*&\[(.*?)\];", rs, re.S).group(1))
    read_only["unsafe_options"].setdefault(program, []).extend(re.findall(r'"([^"]+)"', listed))
(OUT / "read_only.json").write_text(json.dumps(read_only, indent=1, sort_keys=True) + "\n")
print(f"read only: {len(read_only['programs'])} programs")

# ---------------------------------------------------------------------------
# Licences and the notice.
# ---------------------------------------------------------------------------

LICENSES = {
    "TrailDiscover": "LICENSE", "panther-analysis": "LICENSE.txt", "pathfinding.cloud": "LICENSE",
    "iam-dataset": "LICENSE", "claude-code-safety-net": "LICENSE", "shellfirm": "LICENSE",
    "github-mcp-server": "LICENSE", "codex": "LICENSE",
    "sigma": "../Detection-Rule-License/LICENSE.Detection.Rules.md",
}
(OUT / "licenses").mkdir(exist_ok=True)
for name, file in LICENSES.items():
    if (SRC / name / file).exists():
        shutil.copy(SRC / name / file, OUT / "licenses" / f"{name}.LICENSE")
for name in ("pathfinding.cloud", "codex"):
    if (SRC / name / "NOTICE").exists():
        shutil.copy(SRC / name / "NOTICE", OUT / "licenses" / f"{name}.NOTICE")

codex_commit = (SRC / "codex/commit.txt").read_text().split()[-1]
shellfirm_commit = (SRC / "shellfirm/commit.txt").read_text().split()[-1] if (SRC / "shellfirm/commit.txt").exists() else "unknown"
(OUT / "NOTICE").write_text(f"""The rule files in this folder are derived from these open-source works.
Each one's licence is in licenses/.

aws.json
  - iam-dataset by Ian Mckay (https://github.com/iann0036/iam-dataset),
    commit {commit(SRC / 'iam-dataset')}, MIT. Used: the mapping of SDK methods to
    IAM actions and each action's access level, reduced to one access code per
    method and the SDK service names.
  - TrailDiscover by Adan Alvarez (https://github.com/adanalvarez/TrailDiscover),
    commit {commit(SRC / 'TrailDiscover')}, licensed under CC BY 4.0
    (https://creativecommons.org/licenses/by/4.0/). Used: each event's name,
    source and MITRE ATT&CK tactics, and whether it was used in the wild,
    which sets severity. Changed: only events whose calls change something, or
    whose tactic is Credential Access or Exfiltration, are kept.
  - panther-analysis by Panther Labs (https://github.com/panther-labs/panther-analysis),
    commit {commit(SRC / 'panther-analysis')}, Apache-2.0. Used: from the AWS
    CloudTrail rules, each rule's ID, severity, MITRE ATT&CK tactic and the
    event names in its code, checked against iam-dataset; rules about
    console sign-ins or VPC endpoint traffic, and rules naming more than 25
    events, are left out. The rules' other conditions are not used, so
    a call is flagged by name alone.
  - pathfinding.cloud by Datadog (https://github.com/DataDog/pathfinding.cloud),
    commit {commit(SRC / 'pathfinding.cloud')}, Apache-2.0. Used: privilege
    escalation paths that need a single permission.
  - Sigma, as below: AWS CloudTrail rules flag the calls they name, where no
    other source flags them, by name alone (their other conditions are not
    used); the rule's file name is the finding's ID.

github.json
  - panther-analysis, as above: from the GitHub rules, the rule ID, severity
    and tactic for each audit action. The mapping of gh commands to audit
    actions is this project's own.

secrets.json
  - claude-code-safety-net, copyright (c) 2026 J Liew
    (https://github.com/kenryu42/claude-code-safety-net),
    commit {commit(SRC / 'claude-code-safety-net')}, MIT. Used: the names, paths
    and extensions of files that hold secrets, extracted from its rule
    definitions.

shell.json
  - shellfirm by Elad Kaplan (https://github.com/kaplanelad/shellfirm),
    commit {shellfirm_commit}, Apache-2.0. Used: Critical and High checks, without
    the fs, base, network and docker packs, with only git:push_mirror
    and git:push_delete_branch from the git pack (collect.py's own rule ranks
    force pushes by the branch they target), and without the
    "-strict" checks, and without the four checks for running fetched code
    (shell:curl_pipe_to_shell, wget_pipe_to_shell, eval_curl and
    curl_pipe_to_interpreter), which collect.py's own rule replaces so it can
    rank the code by its source. Changed: converted from YAML to JSON; each
    check gained a MITRE ATT&CK tactic decided by its ID.

mcp_tools.json
  - github-mcp-server by GitHub (https://github.com/github/github-mcp-server),
    commit {commit(SRC / 'github-mcp-server')}, MIT. Used: each tool's name and
    whether its readOnlyHint annotation is set, from pkg/github/__toolsnaps__.
  The other servers' lists, the SQL tools and the verbs are this project's
  own, from each server's tool documentation (named in the file).

sigma.json
  - Sigma rules by the SigmaHQ project and each rule's authors
    (https://github.com/SigmaHQ/sigma), commit {commit(SRC / 'sigma')},
    licensed under the Detection Rule License (DRL) 1.1
    (https://github.com/SigmaHQ/Detection-Rule-License; its text is in
    licenses/sigma.LICENSE). Each rule's title, authors ("author" field) and
    link are in the file's "rules", shipped with the tool. Used: Linux and macOS process_creation rules
    of level medium, high or critical, without those whose only tactics are
    Discovery, Reconnaissance or Collection, those that need fields the logs
    don't hold (parent process, user) and those that fall below the
    precision bar on coding agents' commands. Changed: each rule's detection
    is converted to one regular expression on the program and its command
    line; the level sets the severity (critical and high: high; medium:
    medium) and the first ATT&CK tactic tag the tactic (Stealth and Defense
    Impairment: Defense Evasion).

read_only.json
  - Codex by OpenAI (https://github.com/openai/codex), commit {codex_commit},
    Apache-2.0; its NOTICE is in licenses/codex.NOTICE. Used: the commands
    its is_safe_command.rs runs without asking (the "known safe" list) and the
    options that make find, rg and base64 unsafe, extracted from the source.
    collect.py reports no Sigma or shellfirm rule on such a command (unless
    its output is piped into a shell); reading a secret file with it still
    counts.

known_sources.json is this project's own compilation: the official install
scripts of well-known tools, each with the page of the tool's documentation it
was checked against (in the row's "source"), and lists of code host
organisations and of hosts whose content anyone can publish.

well_known_hosts.json is this project's own short list of well-known services
(code hosts, package registries, the major clouds, AI providers, common SaaS),
used only by the report.

Of the Apache-2.0 works, pathfinding.cloud and Codex ship a NOTICE file; they
are in licenses/. shellfirm and panther-analysis ship none at the commits used.
""")
print("notice and licences written")
