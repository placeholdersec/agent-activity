# Using the Claude Code skill

This repository includes a Claude Code skill that builds the same report,
summarises it and answers your questions about it.

## Install the skill

These steps assume the repository is cloned to `~/agent-activity`. Link the
skill once:

```sh
mkdir -p ~/.claude/skills
ln -sfn ~/agent-activity/skill/agent-activity-org-report ~/.claude/skills/agent-activity-org-report
```

## Build the report

In Claude Code, run the skill on the folder that holds the collected files:

```text
/agent-activity-org-report ~/agent-activity/agent-activity-files
```

Once the report is ready, you can ask follow-up questions in the same
conversation.
