# File Created In User Startup Folder

[Rule](../../rules/startup_folder_file_creation.yml)

## Data source

Sysmon Event 11 with TargetFilename and Image. Confirm the field types and event channel after ingestion.

## Test case

A file creation fixture in the Startup path should match. Use the Documents path for the negative control.

## False-positive notes

IT software deployment can legitimately place shortcuts in Startup.

## Triage

Identify the creating process and user. Review timestamps, file properties, signer and any recent changes to related startup entries.
