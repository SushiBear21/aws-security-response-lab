# Demonstration Guide

## Purpose

Present the lab in approximately five to seven minutes using existing
evidence. No new security-group changes or response executions are needed.

## 1. Explain the architecture

Open the repository README.

Show the detection, finding integration, and approved-response diagrams.

Explain that detection and notification are automated, while quarantine
requires an operator-created proposal and explicit approval.

## 2. Show detection and investigation

Open the downloaded incident and timeline evidence from Lessons 4 and 5.

Explain:

- CloudTrail identifies the configuration-change event.
- The detector observes current security-group configuration.
- AWS Config supplies historical configuration context.
- Public SSH receives a HIGH classification in the tested scenario.
- An older Config capture is historical evidence, not proof of current state.

Show the event, incident, timeline, and completion files.

Describe the SHA-256 checks performed against the completion manifest.

## 3. Show notifications and finding integration

Show the received incident, GuardDuty, and Security Hub notifications.

Use the saved Lesson 7 evidence to demonstrate both finding routes.

Explain that sample findings validate integration without demonstrating
detection of an actual compromise.

Acknowledge that Security Hub GetFindings listing remained unresolved.

## 4. Explain approved response

Use the controls matrix and saved response results.

Describe:

- The proposal binds the action to the exact target and security groups.
- Approval binds to the payload hash and expires after ten minutes.
- Execution checks the current resource before changing it.
- A completed response returns already_executed on a sequential repeat.
- Rollback requires a separate proposal and approval.

Show that rejected and expired approval attempts were denied.

Clarify that the target was an unattached interface, not a running workload.

## 5. Show operations and recovery

Open the p3-security-operations dashboard.

Show available invocation, error, duration, and queue metrics.

Describe the controlled recovery exercise:

1. Malformed synthetic input failed during normalization.
2. Lambda delivered its failure record to the processing-failure queue.
3. The recovery tool required explicit operator confirmation.
4. A corrected synthetic fixture processed successfully.
5. The queue message was deleted after success.

Distinguish EventBridge delivery failures from Lambda processing failures.

## 6. Show CI and remote planning

Show the successful offline checks and Reviewed Terraform plan workflow.

Successful planning run:
https://github.com/SushiBear21/aws-security-response-lab/actions/runs/40944883758

Explain that GitHub used temporary OIDC credentials and accessed the
encrypted remote state.

The recorded plan proposed three Lambda package updates, with no resource
additions or deletions. It did not apply changes.

## 7. Close with scope and improvements

Open security-controls-matrix.md.

Explain the difference between demonstrated behavior, configured controls,
and production recommendations.

Discuss independent approvers, running-workload isolation testing,
persistent deduplication, deployment approval, and measured billing costs
as remaining improvements.