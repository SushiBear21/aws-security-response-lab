# Session 7 — Finding integration results

Test date: October 29, 2026.

## Configuration

- GuardDuty detector: e5420c529e3b4586859534fefb472e5e.
- Region: us-east-1.
- Foundational monitoring enabled.
- Optional S3, EKS audit, EBS malware, RDS login, and Lambda network
  protection features explicitly disabled through Terraform.
- Security Hub CSPM enabled with no enabled standards.
- GuardDuty product integration enabled.

## Verified automatic-routing exercise

A sample UnauthorizedAccess:EC2/TorRelay finding was requested at
approximately 2026-10-29T17:58:02Z.

Finding ID: 82e2db71b50c49a58d04c027edb02663.

| Path | Outcome | Router receipt to SNS publication |
| --- | --- | --- |
| GuardDuty | Routed; confirmed_sample | 0.441 seconds |
| Security Hub CSPM | Routed; matching GuardDuty finding ARN | 0.320 seconds |

GuardDuty request ID:
660e9131-0923-4413-a3ed-5dc43f6921cb.

Security Hub request ID:
20cf8225-1ac1-41a9-a54b-d03203e6c45c.

GuardDuty SNS message ID:
53735787-276c-5435-b3de-34daac01efcc.

Security Hub SNS message ID:
f1e74563-2d96-549d-974c-263ea6ec13c6.

Both automatic-route evidence sets were downloaded.
The event.json and finding.json hashes matched their completion manifests.

Both GuardDuty and Security Hub CSPM automatic-route email
notifications were received. Exact inbox arrival times were not measured.

## Correlation

The Security Hub finding ID contains the same GuardDuty finding ID.
These are two observations of one sample finding.

The direct GuardDuty record contains a recognized sample marker.
The Security Hub normalizer reports not_confirmed; its sample provenance
is established by correlation with the confirmed GuardDuty sample.

## Diagnostic exercise

An earlier TorClient finding was replayed directly into Lambda.
The initial replay used API field capitalization and was ignored.
A corrected reconstructed event was processed successfully.

That direct invocation is diagnostic evidence only.
It is excluded from the automatic-routing measurements above.

The reason the original TorClient finding did not produce an observed
automatic delivery was not established.

## Open issue: Security Hub listing

GetFindings returned zero findings despite a captured, automatically
routed Security Hub Findings - Imported event.

An exact-ID query and an exact-ID query with Sample=true also returned
zero findings. The cause remains unresolved.

Automatic EventBridge delivery was verified independently through
Lambda logs and stored event evidence. Current API listing verification
is not claimed as passed.

## Scope and limitations

Sample findings validate integration, not real threat detection.
No malicious traffic was generated.
No quarantine was requested by the finding router.

Original service severity formats were preserved.
Router timing excludes service detection and inbox delivery latency.

Persistent duplicate suppression, recovery, and load testing remain
later work. Hashes establish agreement with the stored manifest,
not independent evidence immutability.

GuardDuty and Security Hub remain enabled and must be included in
cost tracking and teardown planning.