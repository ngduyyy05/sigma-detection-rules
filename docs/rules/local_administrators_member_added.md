# Member Added To Built-in Administrators

[Rule](../../rules/local_administrators_member_added.yml)

## Data source

Security Event 4732 and TargetSid. Confirm the field types and event channel after ingestion.

## Test case

A 4732 fixture for the Administrators alias should match. Change the alias SID for the negative control.

## False-positive notes

Group maintenance and endpoint management frequently add approved principals.

## Triage

Resolve the member SID, actor and host. Compare to approved change records and inspect nearby privilege or logon activity.
