# Failed Remote Interactive Logon

[Rule](../../rules/remote_interactive_logon_failure.yml)

## Data source

Security Event 4625 and LogonType 10. Confirm the field types and event channel after ingestion.

## Test case

A fixture with 4625 and type 10 should match. Change the type to 3 for the negative control.

## False-positive notes

Mistyped credentials and disconnected sessions can produce failures.

## Triage

Review the target account, source address, failure reason and any subsequent successful 4624. Compare the frequency against the account baseline.
