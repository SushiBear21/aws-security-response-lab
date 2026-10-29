# Session 8A — Monitoring and controlled recovery

Test date: October 29, 2026.

## Verified results

- CloudWatch dashboard displayed exercise data.
- Alarm email received.
- Synthetic recovery finding notification received.
- Malformed event failed during normalization.
- Processing-failure queue captured one message.
- Corrected synthetic fixture processed successfully.
- Recovery call duration: 2.605 seconds.
- Router receipt-to-SNS-publication time: 1.903 seconds.
- Failed message deleted after successful recovery.
- Final queue counts: 0 visible, 0 in flight.

Individual alarm identities and final alarm states were not recorded
in these results.

## Evidence references

- Test ID: 1967cf0b-27ec-453f-b709-b55a4b6afc9e
- Failed invocation: 88648fd7-79eb-4079-b2e2-b3772de155be
- Recovery invocation: 94c00b7b-d4c2-4811-a7d2-e3fdcceee7d5
- Queue message ID: 019d5b82-a4b5-48de-8aeb-630c34524341
- Recovery SNS message ID: fa185314-81b0-5974-bd8d-30491043714a

Local records:
- reports/recovery-failure-record.json
- reports/recovery-success.json

## Recovery behavior

The malformed event failed before evidence writes or SNS publication.
An operator explicitly authorized repair of the synthetic fixture.
The utility recorded successful processing before deleting the failed message.

The recovery finding's sample marker was supplied by the exercise.
It was not a newly generated GuardDuty service finding.

## Validation boundaries

Processing-failure capture and controlled repair were exercised.
The EventBridge delivery-failure queue is configured but was not exercised.

No quarantine action was invoked.
Persistent finding deduplication, partial-side-effect recovery, and
concurrent execution testing remain outstanding.

The local recovery-success marker prevents ordinary sequential reruns
of this utility. It is not a distributed exactly-once guarantee.