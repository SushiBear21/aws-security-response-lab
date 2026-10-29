# Lesson 5 notification results

- Test date: October 29, 2026.
- Source event time: 2026-10-29T15:27:25Z.
- Incident ID: 7c37cbf1-d100-475f-b7c0-d5c1e600d4ff.
- Target resource: sg-0c0d98ed7d3c83e75.
- Severity: HIGH.
- Attached network interfaces observed: 0.
- Email subscription: Operational; alert email received.
- Email evidence URI: Used successfully to download this incident's evidence.
- Incident and completion IDs: Matched.
- SNS publication status: published.
- SNS message ID: 2fab9f42-06ae-5241-81b6-fc1f6e8db245.
- Persistence-to-publish time: 0.167 seconds.
- Detection-to-publish time: 3.274 seconds.
- SNS publication time: 2026-10-29T15:27:31.435278Z.
- Exact email arrival time: Not recorded.
- Artifact hashes: event.json, incident.json, and timeline.json matched complete.json.
- Test rule removal: Awaiting recorded cleanup verification.
- Final inbound permissions: Awaiting recorded verification.

## Acceptance result

The persistence-to-SNS-publication target of 30 seconds was met:
observed latency was 0.167 seconds.

Successful SNS publication and receipt of the alert were observed.
Inbox delivery latency was not measured.

## Incident timeline

| Event | UTC timestamp |
| --- | --- |
| AWS Config capture | 2026-10-29T15:20:15.003000Z |
| Source authorization | 2026-10-29T15:27:25Z |
| Handler received event | 2026-10-29T15:27:28.160994Z |
| Source event accepted | 2026-10-29T15:27:28.161063Z |
| Current configuration observed | 2026-10-29T15:27:30.631888Z |
| Investigation completed | 2026-10-29T15:27:30.734010Z |
| Incident persisted | 2026-10-29T15:27:31.267947Z |
| SNS publication succeeded | 2026-10-29T15:27:31.435278Z |

The Config snapshot predates the source event. It supplies earlier
configuration context; the live EC2 inspection supports the current
public SSH finding.

## Runbook exercise

The alert evidence URI was used to download all four evidence files.
The incident and completion identifiers were compared successfully.
Severity, target resource, and attachment count were inspected.
Notification timing, SNS message ID, and the timeline were reviewed.
All three artifact hashes matched the completion manifest.

Cleanup verification remains to be recorded.

## Issues and limitations

A local directory-listing command initially referenced reports/lesson
instead of reports/lesson5. The downloads had succeeded; correcting
the listing path resolved the issue.

This test demonstrates one correlated HIGH notification.
It does not establish production delivery reliability.

Duplicate notification handling and failure recovery remain later work.
No quarantine action was executed.
Hashes establish agreement with the manifest, not independent immutability.