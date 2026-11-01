# Development

`agent-activity.py` is generated from the files in `source/`. Edit those files,
never the generated script.

## Project layout

| Path | Contents |
|---|---|
| `source/collect.py` | Collects activity from the logs |
| `source/report.py` | Builds the report |
| `source/rules/` | Detection rules as JSON |
| `source/templates/report.html` | The report template |
| `source/assets/` | Fonts and images used in the report |
| `agent-activity.ps1` | Windows launcher: finds Python and runs `agent-activity.py` beside it. Written by hand, not generated. |

The rules are derived from iam-dataset, TrailDiscover, panther-analysis,
pathfinding.cloud, Sigma, claude-code-safety-net and shellfirm.
`source/rules/NOTICE` and `source/rules/licenses/` describe what was taken from
each.

## Run from source

Run the source directly, without `-I`, which would hide `report.py`:

```sh
python3 source/collect.py
python3 source/collect.py report FOLDER
```

## Rebuild and test

After a change, rebuild the script and run the tests:

```sh
python3 source/bundle.py
python3 -m unittest discover -s tests
```

## Verify a copy

To check that a given `agent-activity.py` matches this source, copy it to
`/tmp/given.py`, rebuild and compare:

```sh
cp agent-activity.py /tmp/given.py
python3 source/bundle.py
cmp agent-activity.py /tmp/given.py && echo same
```

## Rebuild the rules

Clone the rule sources into one folder, then run the build script, which
requires PyYAML:

```sh
python3 source/build_rules.py <folder>
```

## Rank code sources

`source/rules/known_sources.json` assigns a risk level to code an agent fetched
and ran (`curl … | sh`, `sh -c "$(curl …)"`), or to a package it installed from
a URL, based on where the code came from:

| Source | Risk |
|---|---|
| A well-known installer from its official address, with the version named | Low |
| A well-known installer without a version | Medium |
| Any other source | High |

This list is maintained by the project, with the documentation page for each
row. You can edit it without changing any code.
