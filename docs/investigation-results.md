# Lesson 4 — Investigation results

Test date: October 29, 2026.

## Live test results

| Case | Expected | Observed | Event-to-classification time |
| --- | --- | --- | --- |
| Public TCP 22 | HIGH | HIGH | 6.283 seconds |
| Public TCP 443 | INFO | INFO | 7.919 seconds |
| Private TCP 22 | INFO | INFO | 3.603 seconds |

All three cases produced their expected classification.
There were zero false positives across the two benign test cases.
This small test set does not establish a production false-positive rate.

## Incident references

- Public SSH: 1721f49e-f5d8-481c-a045-7136e9700844
- Public HTTPS: b330b652-b892-4893-8970-313abef33238
- Private SSH: cb4f7e10-57a1-4502-b00a-cb5f33b32d1f

## Public SSH investigation

- Classification: public_ssh_configuration_observed.
- Severity: HIGH.
- Attached network interfaces observed: 0.
- Source authorization time: 2026-10-29T15:09:36Z.
- Current configuration observation: 2026-10-29T15:09:42.182779Z.
- Incident persistence: 2026-10-29T15:09:42.808369Z.
- AWS Config capture: 2026-10-29T15:03:34.615Z.

The Config snapshot predates the test event and supplies earlier
configuration context. The live EC2 inspection establishes that the
public SSH rule was present at investigation time.

## Evidence verification

The downloaded event.json, incident.json, and timeline.json hashes
matched the corresponding values in complete.json.

Hashes establish agreement with the downloaded manifest; they do not
independently establish tamper-proof evidence.

## Cleanup

The controlled test rules were removed.
A final EC2 query returned an empty inbound permissions list.

## Interpretation and limitations

HIGH represents the exercise's public SSH configuration policy.
It does not establish compromise or network reachability.

Current configuration is observed after the API event and can differ
from configuration at the time of that event.

The detector monitors successful AuthorizeSecurityGroupIngress events
for one configured security group. Other configuration-change APIs
are not covered by this lesson.

Investigation read permissions have broad resource scope. Application
logic restricts queries to the configured security group and VPC.

Duplicate suppression, failure recovery, alarms, and quarantine
approval are scheduled for later lessons.