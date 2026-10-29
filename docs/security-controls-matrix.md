# Security Controls Matrix

Project: AWS Cloud Security Detection and Response Lab
Evidence review date: 2026-10-29
Environment: Personal AWS sandbox, us-east-1

## Purpose and scope

This document maps selected lab capabilities to NIST SP 800-53
Revision 5 controls.

The mappings are an implementation crosswalk, not a formal control
assessment, authorization, or claim of NIST or FedRAMP compliance.

Testing used controlled configuration changes, synthetic findings,
and an unattached network interface. No production workloads or
classified information were used.

## Status definitions

- Demonstrated: The listed lab behavior was observed in a recorded test.
- Configured: Configuration exists, but the stated outcome was not
  independently exercised.
- Recommended: A production improvement that this lab has not implemented.

A demonstrated behavior supports part of a control. It does not establish
that every requirement or enhancement of that control is satisfied.

## Implementation and evidence matrix

| Control | Lab implementation | Status | Actual evidence | Limitations |
| --- | --- | --- | --- | --- |
| AC-3 — Access Enforcement | Response execution checks proposal state, payload hash, expiration, target identity, and expected security groups. | Demonstrated | Rejected run `af3041e4da1c489c98a32a8b8d55787e` and expired run `9b21810889454a169e13b69c3c3170f4` were denied; the interface retained its baseline group. See `app/response.py`. | The local operator has administrator access and can bypass the workflow through AWS APIs. |
| AC-5 — Separation of Duties | Proposal and approval are separate workflow steps. | Recommended for independent enforcement | Approval records identify the approving AWS principal. | The same operator created and approved proposals. Independent requester and approver roles were not demonstrated. |
| AC-6 — Least Privilege | Lambda roles restrict evidence writes, notification publishing, and response changes. GitHub uses a separate planning role. | Demonstrated for tested operations | CloudTrail recorded a denied response operation before the required security-group permission was added. GitHub planning later completed as `p3-github-plan`. | Some discovery permissions require broad resource scope. No exhaustive least-privilege or privilege-escalation assessment was performed. |
| AU-3 — Content of Audit Records | Incident records include event identity, actor reference, resource, region, timestamps, classification, and request IDs. | Demonstrated | Incident `7c37cbf1-d100-475f-b7c0-d5c1e600d4ff` and its event, timeline, and completion files. | Audit field coverage was checked for selected lab events, not every AWS operation. |
| AU-6 — Audit Record Review, Analysis, and Reporting | CloudTrail events are enriched with current EC2 configuration and AWS Config history. HIGH classifications request SNS notification. | Demonstrated | Public SSH produced a HIGH classification; private SSH and public HTTPS test cases produced INFO classifications. | The detector covers a narrow event and configuration scenario. Config capture can precede the triggering event. |
| AU-9 — Protection of Audit Information | Evidence is stored in a private, encrypted, versioned S3 bucket. Completion manifests contain SHA-256 hashes. | Demonstrated for hash verification; configured for storage protections | Downloaded incident and finding files matched their completion-manifest hashes. Bucket protections are declared in `infra/terraform/main.tf`. | Hashes detect mismatches against the manifest; they do not prove authenticity if an attacker can replace both. Object Lock and independent immutable storage were not demonstrated. |
| AU-12 — Audit Record Generation | CloudTrail, Lambda logs, and application evidence records capture selected activity. | Demonstrated | CloudTrail authorization events reached the detector; CloudWatch logs correlate processing with Lambda request IDs. | This is not a verified account-wide logging coverage assessment. |
| CM-2 — Baseline Configuration | Terraform declares lab infrastructure and the response interface's baseline security group. | Demonstrated | After rollback, the interface used `sg-0049d812be25b4aaf`; a local Terraform plan reported no changes at that checkpoint. | That result describes the checkpoint. The later GitHub plan proposes three Lambda package updates. |
| CM-3 — Configuration Change Control | Quarantine and rollback require approval bound to an exact payload. GitHub generates a remote Terraform plan. | Demonstrated for response approval and remote planning | Rollback run `f772dd9972a64fbf9b411c149a6433a4` executed after approval. GitHub run `40944883758` completed planning successfully. | The GitHub workflow only plans. Automated apply with enforced deployment approval has not been demonstrated. |
| IR-4 — Incident Handling | Detection, investigation, notification, approved simulated quarantine, verification, and rollback form a bounded response exercise. | Demonstrated | Quarantine run `3ba76d2005fa4205ade9d477666a7b08` and rollback run `f772dd9972a64fbf9b411c149a6433a4`. | Security-group changes were tested on an unattached interface. Isolation of traffic to a running workload was not tested. |
| IR-5 — Incident Monitoring | Incident IDs, timelines, response proposal states, CloudWatch logs, alarms, and a dashboard support investigation tracking. | Demonstrated | Dashboard `p3-security-operations`, incident timelines, response inspection output, and received alarm emails. | There is no centralized case-management system or demonstrated continuously staffed monitoring process. |
| IR-6 — Incident Reporting | SNS publishes triage notifications containing evidence references. | Demonstrated | Incident notification message `2fab9f42-06ae-5241-81b6-fc1f6e8db245`; GuardDuty and Security Hub notifications were also received. | SNS publication time is measured separately from human email receipt. No federal reporting workflow was implemented. |
| SI-4 — System Monitoring | EventBridge routes scoped CloudTrail events and GuardDuty/Security Hub findings to Lambda. | Demonstrated | GuardDuty finding `82e2db71b50c49a58d04c027edb02663` arrived through both finding routes, with evidence and notifications. | Sample findings validate integration, not detection of a real compromise. Security Hub GetFindings returned zero during follow-up queries; this remains unresolved. |
| SI-10 — Information Input Validation | Finding normalization rejects malformed input before evidence writes or notification processing. | Demonstrated | Recovery test `1967cf0b-27ec-453f-b709-b55a4b6afc9e` failed at normalization and reached the processing-failure queue. | Validation was exercised against selected fixtures, not an exhaustive adversarial input set. |
| SC-28 — Protection of Information at Rest | S3 evidence and remote Terraform state use server-side encryption. | Configured; remote state metadata verified | Remote-state HeadObject returned AES256 encryption and a version ID. Evidence encryption is declared in Terraform. | This does not establish customer-managed key requirements, classified-data suitability, or compliance with an organizational cryptographic policy. |
| CP-10 — System Recovery and Reconstitution | A controlled recovery tool repairs a synthetic failed finding, verifies successful processing, and then deletes its queue message. | Demonstrated for the synthetic fixture | Recovery call completed in 2.605 seconds; processing queue returned to zero visible and zero in-flight messages. | This is a narrow recovery exercise, not full service recovery, disaster recovery, or proof of exactly-once processing. |

## Recorded validation results

| Exercise | Observed result | Interpretation |
| --- | --- | --- |
| Public SSH classification | HIGH; 6.283 seconds from source event to classification in the Lesson 4 test. | A controlled public SSH configuration was recognized. |
| Benign comparison cases | Public HTTPS and private SSH produced INFO classifications. | Neither of these two cases produced a HIGH alert; the sample is too small to estimate a general false-positive rate. |
| Incident notification | Detection-to-SNS-publication latency was 3.274 seconds in the Lesson 5 test. | Measures SNS publication, not delivery to a human. |
| GuardDuty route | Router receipt-to-publication latency was 0.441 seconds. | Confirms sample-finding routing and notification. |
| Security Hub route | Router receipt-to-publication latency was 0.320 seconds. | Confirms the imported-finding event route; API listing remained unresolved. |
| Repeat response execution | Returned `already_executed` with the quarantine group still present. | Sequential repeat execution did not repeat the resource change. |
| Rollback | Baseline group restored; approval-to-verification latency was 12.936 seconds. | Confirms rollback for the unattached test interface. |
| Rejected approval | Execution denied; baseline group unchanged. | A rejected proposal could not execute through the response workflow. |
| Expired approval | Execution denied after the ten-minute approval window; baseline group unchanged. | Expiration was enforced at execution. |
| Controlled recovery | Corrected fixture processed; queue message deleted after success; recovery email received. | Demonstrates the tested processing-failure recovery path. |
| Bounded workload | 12 of 12 calls passed: four routed and eight ignored; concurrency three; wall time 5.13 seconds. | Small functional workload exercise, not a production capacity benchmark. |
| Remote Terraform planning | GitHub run `40944883758`: zero additions, three changes, zero deletions. | OIDC authentication, remote-state access, and refresh permissions worked for this run. No apply occurred. |

## Evidence locations

- Incident evidence:
  `s3://security-lab-evidence-359769212511-47e2f18084087725c0094ba897/incidents/`
- Finding evidence:
  `s3://security-lab-evidence-359769212511-47e2f18084087725c0094ba897/findings/`
- Detector logs: `/aws/lambda/p3-security-detector`
- Finding-router logs: `/aws/lambda/p3-finding-router`
- Response logs: `/aws/lambda/p3-security-response`
- Response proposal table: `p3-response-approvals`
- Operations dashboard: `p3-security-operations`
- Local downloaded evidence: `reports/`

Raw evidence is retained separately from this document. Repository ignore
rules exclude local reports and Terraform state. Evidence access requires
appropriate AWS permissions.

## Remaining improvements

These items are recommendations or unverified capabilities, not completed
controls:

1. Enforce independent requester and approver identities.
2. Validate quarantine against a running disposable workload and test traffic.
3. Test concurrent execution, resource changes after approval, and partial
   failures that require manual reconciliation.
4. Add persistent finding deduplication and evaluate duplicate notifications.
5. Exercise EventBridge delivery failures separately from Lambda processing
   failures.
6. Test restoration from a previous Terraform state version.
7. Introduce independently protected or immutable audit evidence.
8. Implement and validate approved deployment automation.
9. Resolve the Security Hub API listing discrepancy.
10. Record actual billed costs after billing data becomes available.

## Reference

NIST SP 800-53 Revision 5:
https://doi.org/10.6028/NIST.SP.800-53r5


| Claim | Evidence | Result |
|---|---|---|
| Quarantine used an unattached interface | Interface status was `available`, with `Attachment: null`. | Confirmed |
| Rejected and expired approvals were denied | Both execution attempts failed; the baseline security group remained unchanged. | Confirmed |
| Rollback restored the baseline group | Rollback returned `executed`, with `sg-0049d812be25b4aaf` observed. | Confirmed |
| GitHub planned without applying | Successful workflow showed **0 additions, 3 changes, 0 deletions** in the plan-only step. | Confirmed |
| Actual billing costs remain pending | You haven’t supplied billed-cost measurements. | Correct to leave pending |