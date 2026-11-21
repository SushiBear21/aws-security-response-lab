# Defensive SIEM, SOAR, and EDR workbench

Replay Windows Sysmon process and network event XML into a local SQLite workbench.
The lab reuses the AWS finding router’s source-specific case identity and
canonical evidence, plus its response checks for payload integrity, approval
expiry, and current state. The endpoint state changes only inside SQLite.

## Reproduce the exercise

Install the pinned Python dependencies from the repository root. Run the demo
on a disposable database and save the evidence report.

```sh
python -m pip install -r requirements-ci.txt
python -m unittest discover -s tests -v
python -m app.endpoint_demo --output endpoint-workbench.json
```

| Fixture path | Expected result |
| --- | --- |
| `ws-alert.lab` runs the lab inventory probe and makes two synthetic outbound connections | One case and a three-event process timeline |
| `ws-tuned.lab` runs the probe to the approved fixture IP and port | One suppression with a recorded reason |
| `ws-noise.lab` runs a different program and connects | Events retained in SIEM counts with zero cases |
| The same seven-event XML is delivered again | Seven duplicate events, zero inserts, zero additional cases |
| Operator requests isolation before approval | Denied. Simulated state stays connected. |
| Reviewer approves the exact isolation proposal and operator retries | Simulated state becomes isolated. A repeat execution makes zero changes. |
| Operator requests rollback before its separate approval | Denied. Simulated state stays isolated. |
| Reviewer approves the exact rollback proposal and operator executes | Simulated state returns to connected with the isolation owner cleared. |

CI publishes `endpoint-workbench.json` as the `endpoint-workbench` artifact in
the **Detection evaluation** workflow. The demo records scripted fixture
approvals and generates fresh proposal IDs and decision timestamps on each run.
Keep local reports and custom telemetry out of Git.

## Analyst runbook

1. **Ingest and verify coverage.** Use a fresh SQLite database with the fixture
   inventory and suppression policy. Run the report and check event counts by
   host and event ID. The parser accepts UTF-8 Event XML or an `Events` wrapper.
   It normalizes Sysmon Event IDs 1 and 3, hashes an identity based on host,
   channel, record number, and UTC timestamp, and excludes command lines and
   user names from the stored fields.

   ```sh
   python -m app.endpoint_workbench --db demo.sqlite ingest --xml tests/fixtures/sysmon-endpoint.xml --policy tests/fixtures/sysmon-policy.json
   python -m app.endpoint_workbench --db demo.sqlite report
   ```

2. **Validate the alert.** The [SIEM SQL](../app/endpoint_siem.py) joins process
   creation and initiated network events on host, process GUID, and image. It
   matches the exact fixture image `C:\Lab\InventoryProbe.exe` when the
   connection occurs within 120 seconds of process creation. The case identity
   includes the rule, host, and process GUID, so retries and additional matching
   connections enrich the timeline without opening additional cases. Treat the
   alert as a request to investigate an inventory pattern. In the fixture, the
   underlying activity is benign.
3. **Review enrichment and tuning.** Compare the asset owner and criticality,
   the normalized trigger, the timeline, and their SHA-256 digests. Suppression
   requires an exact host, image, destination IP, and port with a reason. To test
   a tuning change, replay into a fresh database and compare expected alerts,
   suppression, and negative cases. The policy hash stays fixed for each
   database. A case with an unknown asset remains available for triage, with
   simulated containment blocked.
4. **Propose and review simulated isolation.** Replace `CASE_ID` with the case
   ID from the report. The reviewer checks scope, target, evidence hash, and
   expected and desired states in `payload_json`. The final two commands use the
   proposal’s `run_id` and full `payload_sha256`. Approval expires after ten
   minutes. As a negative check, run execution before approval and confirm
   the denial and unchanged state in `report`.

   ```sh
   python -m app.endpoint_workbench --db demo.sqlite propose --case CASE_ID --action isolate
   python -m app.endpoint_workbench --db demo.sqlite approve --run RUN_ID --digest PAYLOAD_SHA256
   python -m app.endpoint_workbench --db demo.sqlite execute --run RUN_ID
   ```

5. **Roll back and verify.** Run `propose --case CASE_ID --action rollback`.
   Review, approve, and execute its new run ID and digest using the same CLI.
   Confirm `simulated_state` is `connected`, `isolation_owner` is null, and the report
   shows separate proposal, approval, and execution records. Save the case and
   decision report with the different approval digests. The endpoint generation
   also invalidates older approvals after a state transition, including after a
   rollback restores the original state.

## Optional benign telemetry on an owned Windows lab VM

Use an existing [Sysmon installation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
configured to log process creation (ID 1) and network connections (ID 3).
Review the VM’s current filters. Microsoft documents that network connection
logging requires configuration. The workbench’s CI exercise uses synthetic XML.
Native Windows collection and optional localhost coverage still need a VM run.

1. In one PowerShell window, use an empty directory and start an HTTP server
   bound to the loopback interface. Stop the server with Ctrl+C after export.

   ```powershell
   $webRoot = Join-Path $env:TEMP ('sysmon-lab-' + [guid]::NewGuid().ToString('N'))
   New-Item -ItemType Directory -Path $webRoot | Out-Null
   Set-Content -LiteralPath (Join-Path $webRoot 'probe.txt') -Value 'benign lab telemetry'
   python -m http.server 8080 --bind 127.0.0.1 --directory $webRoot
   ```

2. In another PowerShell window, record a start time, make a loopback request,
   and export matching event types from the Sysmon Operational channel. Review
   the XML locally because a time-window export can contain unrelated system
   activity. If ID 3 is missing, check that Sysmon filters include the program
   and loopback connection, then repeat the collection.

   ```powershell
   $start = Get-Date
   curl.exe --fail http://127.0.0.1:8080/probe.txt
   Start-Sleep -Seconds 3
   $events = Get-WinEvent -FilterHashtable @{
       LogName = 'Microsoft-Windows-Sysmon/Operational'
       Id = 1, 3
       StartTime = $start
   } -MaxEvents 200
   if ($events) {
       $xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'
       [System.IO.File]::WriteAllText(
           (Join-Path (Get-Location).Path 'sysmon-lab.xml'), $xml, [Text.UTF8Encoding]::new($false))
   }
   ```

3. Ingest the export into a separate local database and check the counts. The
   loopback activity exercises the telemetry path. The fixture XML exercises the
   exact probe-image rule and simulations. Keep the private XML on the VM or in
   private lab storage.

## Evidence and boundaries

Fixture hosts, programs, IPs, asset owners, and response actions are synthetic.
The simulation tracks an isolation owner in SQLite with no endpoint agent,
vendor console, actual network controls, or AWS resources. Local reviewer and
operator labels describe workflow roles, and SQLite and the JSON export have
no independent identity enforcement or tamper-resistant storage. The hashes
support evidence comparison within the lab. Event forwarding, native Windows
collection, vendor integrations, and operation against live endpoints remain
unverified.
