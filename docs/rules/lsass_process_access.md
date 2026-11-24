# Process Requesting Read Access to LSASS

[Rule](../../rules/lsass_process_access.yml)

## Data source

Sysmon Event 10 with TargetImage and GrantedAccess. Confirm the field types and event channel after ingestion.

## Test case

A fixture with an LSASS target and access 0x1010 should match. Change the target to a disposable lab process for the negative control.

## False-positive notes

Depending on the endpoint, legitimate security utilities may request matching access.

## Triage

Check the source binary, signer and process ancestry. Review the call trace, neighboring events and any evidence of an actual credential exposure.
