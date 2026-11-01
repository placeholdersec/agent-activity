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
| Intune | Go to **Devices > macOS > Scripts > Add (shell script)**, upload the file, and set **Run script as signed-in user** to **No**. For Windows, see [Windows with Intune](#windows-with-intune). |
| Mosyle | Go to **Management > Custom Commands** and paste the file. |

Running as root, the script reads every user's Claude Code and Codex logs, each
as that user. It saves `agent-activity-<serial number>.json` to a folder only
root can read:

- **macOS:** `/Library/Application Support/AgentActivity/`
- **Linux:** `/var/lib/agent-activity/`
- **Windows:** `%ProgramData%\AgentActivity\`, readable only by administrators
  and SYSTEM. If that folder already exists and someone else owns it or can
  open it, the script stops; delete the folder and run it again.

> [!TIP]
> To try it on one Mac first, collect the activity and then build the report:
>
> ```sh
> sudo python3 -I agent-activity.py
> sudo python3 -I agent-activity.py report "/Library/Application Support/AgentActivity"
> ```

### Windows with Intune

On Windows the collector runs as SYSTEM and reads every profile listed in the
registry that holds Claude Code or Codex logs. Each machine needs Python 3.9 or
later installed for all users, for example python.org's installer with
`InstallAllUsers=1` deployed as its own app. The Microsoft Store's `python3`
stub doesn't count.

The release's `agent-activity.ps1` runs `agent-activity.py` from its own folder
with the first suitable Python it finds: `py -3`, then `python.exe` on the
`PATH`, then the `Python3*` folders under Program Files. It passes its
arguments on. As SYSTEM it ignores the `PATH` and only takes the Pythons that
`%SystemRoot%\py.exe` lists and those under Program Files. As SYSTEM or an
administrator it runs a Python only if no one but SYSTEM, Administrators and
TrustedInstaller can change its folder, `python.exe`, the DLLs beside it, its
`Lib`, `DLLs` and `Lib\site-packages` folders or a `.pth` file in
`site-packages`, and `agent-activity.py` only from a folder they alone can
change. So install Python for all users, to the default folder under Program
Files, and keep both scripts in such a folder, as the platform script below
does with `%ProgramFiles%\AgentActivity`. A per-user Python, even the
administrator's own, is refused.

Choose one of these ways to deploy it:

| Method | Best for | How |
|---|---|---|
| Win32 app | Running again on a schedule or after changes | Package `agent-activity.py` and `agent-activity.ps1` with the Microsoft Win32 Content Prep Tool. Set the install command below, **Install behavior** to **System**, and a detection rule that the folder `%ProgramData%\AgentActivity` exists. |
| Platform script | A single run on each device | Go to **Devices > Windows > Scripts and remediations > Platform scripts > Add**. Intune sends one file, so the script must download both files and check them against `SHA256SUMS` (see below). Set **Run this script using the logged on credentials** to **No** and **Run script in 64 bit PowerShell Host** to **Yes**. |

The Win32 app's install command:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File agent-activity.ps1 --upload "LINK"
```

A platform script that pins one release. Copy the two hashes from that
release's `SHA256SUMS`:

```powershell
$release = 'https://github.com/placeholdersec/agent-activity/releases/download/vX.Y.Z'
$sums = @{ 'agent-activity.py' = 'HASH'; 'agent-activity.ps1' = 'HASH' }
$dir = Join-Path $env:ProgramFiles 'AgentActivity'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
foreach ($file in $sums.Keys) {
    $path = Join-Path $dir $file
    Invoke-WebRequest "$release/$file" -OutFile $path -UseBasicParsing
    if ((Get-FileHash $path -Algorithm SHA256).Hash -ne $sums[$file]) { Remove-Item $path; throw "$file does not match" }
}
& (Join-Path $dir 'agent-activity.ps1') --upload 'LINK'
exit $LASTEXITCODE
```

> [!TIP]
> To try it on one Windows machine first, copy both files to a folder only
> administrators can change, such as `%ProgramFiles%\AgentActivity`, and run
> these from an administrator PowerShell there:
>
> ```powershell
> .\agent-activity.ps1
> .\agent-activity.ps1 report "$env:ProgramData\AgentActivity"
> ```
>
> A downloaded `.ps1` may be blocked by the execution policy. Run
> `powershell -ExecutionPolicy Bypass -File .\agent-activity.ps1` instead, or
> call `py -3 -I agent-activity.py` directly.

## Step 2: Gather the files

Have each machine send its file to storage you own. The
[upload guide](upload.md) covers Azure, Amazon S3 and Google Cloud. Then set the
upload link:

- **Jamf Pro:** use parameter 4, and label it "Upload link".
- **Other MDMs:** enter the link between the quotes of `UPLOAD_URL = ""` near the
  top of the file before you add it to the MDM.

> [!NOTE]
> Editing `UPLOAD_URL` changes the file, so it no longer matches `SHA256SUMS` or
> the build verification step. Verify the download first, then edit only that line:
> `diff` against the verified copy should show nothing else. Where you can pass
> arguments, prefer Jamf parameter 4 or `--upload`, which leave the file unchanged.

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
| `1` | The upload failed (the file is kept), Python is missing or too old, or `agent-activity.ps1` found no `agent-activity.py` beside it or, as SYSTEM or an administrator, refused a folder or Python others can change. |
| `2` | An option or the output folder is invalid. |

## Options

| Option | Default | Description |
|---|---|---|
| `--name NAME` | Serial number | The machine's name in the report. Without a serial number (Linux, not as root), it is the start of the hashed machine ID. On Windows the serial number is the BIOS's. |
| `--days N` | `30` | Number of days of logs to read. Claude Code keeps about 30. |
| `--out FILE` | The folder in Step 1 | Where to save the file. `-` prints the JSON instead. |
| `--upload LINK` | None | HTTPS link to send the file to. See the [upload guide](upload.md). |
| `--home DIR` | Every user | Read only this home folder, for testing. Can be repeated. |
