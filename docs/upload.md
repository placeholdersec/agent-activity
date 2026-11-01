# Uploading to your own storage

By default, the collected file stays on the machine. With an upload link, each
machine also sends its file to storage your organisation owns.

## How uploads work

The tool sends one HTTPS `PUT` with `Content-Type: application/json` to the host
the link names, and to no other host. Redirects are refused. If an upload fails,
the file is kept on the machine and the run exits with code 1.

## Set the upload link

Provide the link in one of three ways:

- Pass `--upload LINK` on the command line.
- Set it as parameter 4 in Jamf Pro.
- Enter it between the quotes of `UPLOAD_URL = ""` near the top of
  `agent-activity.py`.

> [!NOTE]
> Editing `UPLOAD_URL` changes the file, so it no longer matches `SHA256SUMS` or
> the build verification step. Verify the download first, then edit only that line:
> `diff` against the verified copy should show nothing else. Where you can pass
> arguments, prefer Jamf parameter 4 or `--upload`, which leave the file unchanged.

Links often hold `&`, so quote them: single quotes in a shell or PowerShell,
double quotes in a Windows command line such as an Intune install command.

`{name}` in the link is replaced with the machine's name, which is its serial
number by default. This gives each machine its own file from a single link.

> [!IMPORTANT]
> Keep the link private. Anyone who has it can write to that location.

## Choose a storage option

| Storage | Best for | Links needed |
|---|---|---|
| [Azure Blob Storage](#azure-blob-storage) | Any size of rollout | One link for every machine |
| [Amazon S3, presigned links](#a-few-machines-presigned-links) | A few machines, run by hand | One link per machine |
| [Amazon S3, bucket policy](#a-fleet-through-an-mdm-bucket-policy) | A fleet, run through an MDM | One link for every machine |
| [Google Cloud Storage, signed links](#a-few-machines-signed-links) | A few machines, run by hand | One link per machine |
| [Your own upload service](#a-fleet-your-own-upload-service) | A fleet on Google Cloud | One link for every machine |

## Azure Blob Storage

A container SAS works as one link for every machine. Grant create and write
permissions only, so machines can't read or list each other's files:

```sh
az storage container create --account-name ACCOUNT --name agent-activity --auth-mode login
az storage container generate-sas --account-name ACCOUNT --name agent-activity \
  --permissions cw --expiry YYYY-MM-DDT00:00Z --auth-mode login --as-user -o tsv
```

Your link is the following address with the printed SAS appended:

```text
https://ACCOUNT.blob.core.windows.net/agent-activity/{name}.json?
```

The tool adds the `x-ms-blob-type: BlockBlob` header that Azure requires.

A SAS signed with your login (`--as-user`) lasts at most 7 days, so set
`--expiry` within a week. For a longer rollout, sign with the account key by
using `--account-key KEY` in place of `--auth-mode login --as-user`.

## Amazon S3

### A few machines: presigned links

Use this option when developers run the tool by hand. Each machine gets its own
link to pass to `--upload`.

`aws s3 presign` creates only download links, so use this command to create
upload links, one for each serial number in `serials.txt`. It requires
`pip3 install boto3`:

```sh
while read s; do python3 -c 'import boto3, sys; print(sys.argv[1], boto3.client("s3", region_name="REGION").generate_presigned_url("put_object", Params={"Bucket": "BUCKET", "Key": "agent-activity/" + sys.argv[1] + ".json"}, ExpiresIn=604800))' "$s"; done < serials.txt
```

A link lasts 7 days when signed with an IAM user's keys. When signed with SSO or
role credentials, it expires along with those credentials, often within hours.

### A fleet through an MDM: bucket policy

Allow your office or VPN addresses to write, and only write, under one prefix,
with no signature:

```sh
aws s3api put-bucket-policy --bucket BUCKET --policy '{"Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": "*", "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::BUCKET/agent-activity/*",
  "Condition": {"IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]}}}]}'
```

Your link is:

```text
https://BUCKET.s3.REGION.amazonaws.com/agent-activity/{name}.json
```

AWS doesn't treat a policy limited to fixed source addresses as public, so Block
Public Access can stay on.

Anyone on those networks can write files to the prefix, but can't read them. A
machine outside those networks is refused and keeps its file until the next run.

## Google Cloud Storage

### A few machines: signed links

Each machine gets its own link to pass to `--upload`, signed as a service
account:

```sh
gcloud storage sign-url gs://BUCKET/agent-activity/SERIAL.json --http-verb=PUT \
  --duration=12h --impersonate-service-account=SA@PROJECT.iam.gserviceaccount.com
```

A link lasts at most 12 hours with `--impersonate-service-account`, or 7 days
with `--private-key-file`.

### A fleet: your own upload service

Cloud Storage has no write-only rule based on source address. For a fleet, run a
small upload service of your own and use its HTTPS address as the link. For
example, a Cloud Run service can check the caller and write to the bucket.
