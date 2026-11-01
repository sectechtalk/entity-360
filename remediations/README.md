# Entity 360 Intune Remediations

Entity 360's own Remediation scripts (Phase 4.6). Not shared with any other project.

| Script | Role | Output |
| --- | --- | --- |
| `Detect-E360NetworkConnectivity.ps1` | Detection only (no remediation script) | One line of compact JSON, under 2,048 characters. Exit 0 healthy, 1 problem. |

Intune settings: run as the logged-on user (Yes), 64-bit PowerShell (Yes), enforce signature check per tenant policy.
Edit the target list in the script's `param` block. Checks: prerequisites (PowerShell 5.1, an active adapter),
DNS per target (3 s), TCP connect per target (3 s), latency (connect time, slow above 1,000 ms), 25 s overall.

JSON keys: `ok`, `pre` (prerequisites), `lat` (min/max/avg ms), `pass`/`total`, `issues`, `r` (per target:
`t` target, `dns`, `ip`, `dnsMs`, `tcp`, `ms`), `trunc` when output was shortened.

## Run now and the audit trail (Phase 4.8)

On Investigate, Remediation results, a user with the `E360.Admin` app role sees **Run now** on each device row.
It asks for a reason (required, up to 500 characters) and then calls
`POST /beta/deviceManagement/managedDevices/{id}/initiateOnDemandProactiveRemediation` with the admin's own
delegated token (`DeviceManagementManagedDevices.PrivilegedOperations.All`, plus an Intune role that allows running
Remediations). Only devices already in the results (the pilot group) can be targeted; the server checks the id.
Nothing runs app-only or with another identity.

Every request (accepted, denied or failed) is recorded with id, UTC time, requester UPN and object id, reason,
device, managed device id, device user, script id, result and Graph error text. Records are kept in memory
(`GET /api/intune/remediation-runs`, E360.Admin, shown as Run requests with CSV export) and written as one JSON line
prefixed `E360_AUDIT ` to stdout, so the Container Apps console log keeps them after a restart.
