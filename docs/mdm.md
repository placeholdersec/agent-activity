# MDM deployment

This guide shows you how to run Agent Activity across your fleet with an MDM and
build one report from the results. You need a single file:
[`agent-activity.py`](../agent-activity.py), at the top of this repository.

## Step 1: Run the script on every machine

Add `agent-activity.py` as a script that runs as root:

| MDM | Where to add it |
|---|---|
| Jamf Pro | Go to **Settings > Computer management > Scripts > New**, paste the file, then add the script to a policy. |
| Kandji | Go to **Library > Custom Script**, paste the file as the audit script, and run it once per device. |
| Intune | Go to **Devices > macOS > Scripts > Add (shell script)**, upload the file, and set **Run script as signed-in user** to **No**. |
| Mosyle | Go to **Management > Custom Commands** and paste the file. |

Running as root, the script reads every user's Claude Code and Codex logs, each
as that user. It saves `agent-activity-<serial number>.json` to a folder only
root can read:

- **macOS:** `/Library/Application Support/AgentActivity/`
- **Linux:** `/var/lib/agent-activity/`

> [!TIP]
> To try it on one Mac first, collect the activity and then build the report:
>
> ```sh
> sudo python3 -I agent-activity.py
> sudo python3 -I agent-activity.py report "/Library/Application Support/AgentActivity"
> ```

## Step 2: Gather the files

Have each machine send its file to storage you own. The
[upload guide](upload.md) covers Azure, Amazon S3 and Google Cloud. Then set the
upload link:

- **Jamf Pro:** use parameter 4, and label it "Upload link".
- **Other MDMs:** enter the link between the quotes of `UPLOAD_URL = ""` near the
  top of the file before you add it to the MDM.

If your MDM can collect files from machines, you can gather them from the folder
in Step 1 instead.

## Step 3: Build the report

Put all the files in one folder, then run:

```sh
python3 -I agent-activity.py report FOLDER
```

The report opens in your browser and is saved in that folder.

## Exit codes

Problems are explained on standard error.

| Code | Meaning |
|---|---|
| `0` | The run succeeded. |
| `1` | The upload failed (the file is kept), or Python is missing or too old. |
| `2` | An option or the output folder is invalid. |

## Options

| Option | Default | Description |
|---|---|---|
| `--name NAME` | Serial number | The machine's name in the report. Without a serial number (Linux, not as root), it is the start of the hashed machine ID. |
| `--days N` | `30` | Number of days of logs to read. Claude Code keeps about 30. |
| `--out FILE` | The folder in Step 1 | Where to save the file. `-` prints the JSON instead. |
| `--upload LINK` | None | HTTPS link to send the file to. See the [upload guide](upload.md). |
| `--home DIR` | Every user | Read only this home folder, for testing. Can be repeated. |
