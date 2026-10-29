# Operations runbook

## Monitoring

Dashboard: p3-security-operations.

Review Lambda invocations, errors, duration, router throttles,
failure-destination delivery errors, and failure-queue depth.

Expected denied approval exercises can produce response Lambda errors.
Correlate alarms with exercise records.

## Failure triage

1. Preserve the failure record, event ID, request ID, and timestamps.
2. Distinguish EventBridge delivery failure from Lambda processing failure.
3. Inspect the logged failure stage and relevant permissions.
4. Inspect existing evidence writes and SNS publication records.
5. Determine whether side effects already occurred before considering replay.

## Controlled recovery

The recovery utility is restricted to the Session 8 synthetic fixture.
Use the explicit RECOVER TEST prompt.
Confirm successful processing, notification, and queue cleanup.

If recovery outcome or message deletion is uncertain, inspect records
before retrying. Do not delete the success marker to force another invocation.

## Response workflow

Never replay quarantine through the finding recovery utility.
Preserve EXECUTING and NEEDS_REVIEW proposal states.
Reconcile actual EC2 configuration with CloudTrail before further action.

## Limitations

An invocation timeout does not establish that no side effect occurred.
A missing completion artifact does not establish that no email was published.
Finding notifications do not yet have persistent duplicate suppression.