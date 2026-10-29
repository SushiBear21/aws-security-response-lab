# Lab incident triage runbook

## Alert meaning

The detector accepted an ingress-authorization event and observed
a current public rule that includes SSH.

HIGH is the lab configuration policy classification.
It does not establish compromise or network reachability.

## Investigation procedure

1. Confirm account, Region, target resource, and incident ID.
2. Locate the attempt directory using the alert evidence URI.
3. Download event.json, incident.json, timeline.json, and complete.json.
4. Verify artifact hashes against complete.json.
5. Inspect source event time, actor reference, and target resource.
6. Review current rules, rule IDs, VPC, and interface attachments.
7. Review Config evidence status and its independent capture time.
8. Correlate incident persistence and SNS publication.
9. Record observed email arrival separately.

## Lab cleanup

Remove the controlled test rule using its recorded rule ID.
Verify that inbound permissions return to the expected baseline.
If unexpected interfaces are attached, stop the exercise and investigate.

## Response boundary

The detector does not execute quarantine.
Human-approved response is introduced in Lesson 6.

## Troubleshooting

- No detector entry: inspect EventBridge routing and Lambda permissions.
- processing_failed: inspect the stage and error category.
- Config unavailable: inspect recorder status and history permissions.
- SNS published but no email: check subscription and email delivery.
- Missing complete.json: treat the attempt as incomplete.
- Hash mismatch: preserve the files and investigate.

## Limitations

Current configuration can differ from configuration at source-event time.
Hashes establish agreement with the manifest, not independent immutability.
Retries may produce repeated attempts and notifications.
Duplicate suppression and recovery are later work.