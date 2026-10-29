# Lesson 6 — Human-approved AWS response

Test date: October 29, 2026.

## Exercise

A dedicated, unattached network interface was moved from a baseline
security group to an empty quarantine group, then restored through
a separately approved rollback.

This demonstrates configuration isolation, not traffic isolation of
a running workload.

## Resources

- Interface: eni-0ef1cd1c2c22baf53
- Baseline group: sg-0049d812be25b4aaf
- Quarantine group: sg-0f770a21d7ed76c60

## Observed results

| Test | Result |
| --- | --- |
| Pending proposal execution | Denied |
| Incorrect approval phrase | Denied |
| Approved quarantine | Executed; quarantine group verified |
| Sequential repeat execution | already_executed; desired state still present |
| Separately approved rollback | Executed; baseline restored |
| Rejected proposal execution | Denied; baseline unchanged |
| Expired approval execution | Denied; baseline unchanged |
| Terraform plan after rollback | No changes |

Rollback approval-to-verification latency was 12.936 seconds,
meeting the 60-second exercise target.

Quarantine latency is retained in the workflow record and is not
transcribed here.

## Workflow references

- Initial failed attempt: 466c152ea48f4ad8979b95f2f1b57dfa
- Successful quarantine: 3ba76d2005fa4205ade9d477666a7b08
- Rollback: f772dd9972a64fbf9b411c149a6433a4
- Rejection test: af3041e4da1c489c98a32a8b8d55787e
- Expiration test: 9b21810889454a169e13b69c3c3170f4

## Expiration evidence

Approval expired at 2026-10-29T17:29:54Z.

Request 894dbf01-e56a-4958-b5e5-12e3db970c14 started at
2026-10-29T17:32:18Z and was denied.

A subsequent attempt after 13:33:28 Eastern was also denied.
An independent EC2 query confirmed the baseline group remained assigned.

## Initial failure and correction

The first approved attempt encountered Client.UnauthorizedOperation.
CloudTrail showed that ModifyNetworkInterfaceAttribute also required
authorization on the destination security group.

The Terraform policy was corrected to authorize the dedicated interface
and the two response security groups.

The failed proposal remained NEEDS_REVIEW.
A fresh proposal was approved and executed successfully.

## Response runbook

1. Inspect the exact proposal and target interface.
2. Confirm the interface is dedicated, available, and unattached.
3. Review expected groups, desired groups, and payload hash.
4. Approve the displayed payload-specific phrase.
5. Execute before approval expires.
6. Independently verify the resulting security groups.
7. Create and approve a separate rollback proposal.
8. Verify baseline restoration and review the Terraform plan.

For NEEDS_REVIEW or a stuck EXECUTING state, preserve the record.
Inspect the actual resource and CloudTrail history.
Do not reset the state to force another execution.

## Security boundaries and limitations

Approval records include the exact payload hash, approver identity,
and expiration. The executor validates the target and current groups.

A conditional DynamoDB transition allows one execution claim.
Sequential replay behavior was tested; concurrency was not tested.

Resource inspection and EC2 modification are separate operations.
A race with an external administrator remains possible.

The lab operator uses administrator SSO access. Independent separation
of approver and executor administration is not established.

The incident reference is an operator-supplied exercise association,
not proof that the response interface was implicated in that incident.

Workflow records and logs are not independently immutable.

Partial-failure recovery, concurrent execution, and changed-resource
tests remain future validation work.