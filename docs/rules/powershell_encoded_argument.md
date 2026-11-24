# PowerShell Process With Encoded Command Argument

[Rule](../../rules/powershell_encoded_argument.yml)

## Data source

Sysmon Event 1 with Image and CommandLine. Confirm the field types and event channel after ingestion.

## Test case

A fixture with a PowerShell image and an encoded-command switch should match. Replace the switch with -File for the negative control.

## False-positive notes

Some deployment platforms pass encoded scripts for quoting and transport.

## Triage

Review parent image, signer and process lineage. Decode recorded content as text in an offline viewer and compare with script-block events.
