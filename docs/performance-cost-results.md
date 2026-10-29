Session 8B — Bounded workload and cost evidence
Test date: October 29, 2026.
Status: workload verified; billing and selected operational checks pending.
Workload results
- Run ID: c6bf5cd2857c411e86f44feb75c4b261.
- UTC start: 2026-10-29T18:31:46.886291Z.
- UTC finish: 2026-10-29T18:31:52.016828Z.
- Local time: approximately 2:31 PM Eastern.
- Target: p3-finding-router in us-east-1.
- Submitted requests: 12.
- Maximum concurrent requests configured: 3.
- Successful expected outcomes: 12 of 12.
- Completed synthetic findings: 4 of 4.
- Ignored out-of-scope events: 8 of 8.
- Function errors reported by runner: 0.
- Client errors reported by runner: 0.
- Wall duration: 5.130 seconds.
- Observed request completion throughput: 2.339 requests per second.
All submitted requests were accounted for. This throughput describes one
bounded mixed workload; it is not a maximum capacity measurement.
Client latency
Path	Successful sample count	Median	Maximum
Routed finding	4	2.302 seconds	3.278 seconds
Ignored event	8	0.677 seconds	0.740 seconds


Case	Expected	Actual	Client latency, seconds
0	complete	complete	1.400
1	complete	complete	3.204
2	complete	complete	3.278
3	complete	complete	1.003
4	ignored	ignored	0.659
5	ignored	ignored	0.681
6	ignored	ignored	0.715
7	ignored	ignored	0.673
8	ignored	ignored	0.647
9	ignored	ignored	0.688
10	ignored	ignored	0.672
11	ignored	ignored	0.740


Timing includes synchronous request/response overhead. Client setup occurs
before the timed workload. GuardDuty detection, EventBridge delivery, and
inbox arrival are outside the measurement. Cold starts are visible in the
supplied Lambda logs; this is not a warm-only benchmark.

The sample is too small to establish production capacity or a stable
tail-latency percentile.
Operational observations
- All four finding cases returned complete, which follows successful SNS
  publication and completion-artifact storage in the deployed handler.
- Four synthetic finding emails: inbox receipt not yet confirmed for this run.
- No workload function or client errors were reported.
- The earlier normalization error at 18:22:23 UTC belongs to the separate
  Session 8A failure exercise and is excluded from this workload's results.
- Processing-failure queue before and after the test: 0 visible, 0 in flight.
- Response interface eni-0ef1cd1c2c22baf53 remained assigned to baseline group
  sg-0049d812be25b4aaf after the test.
- No quarantine action was invoked by the workload runner.
- Dashboard display for this specific workload: not yet confirmed.
- Aggregate CloudWatch throttling metrics for the test window: not supplied.
  No throttling failure was reported by the runner.
Synchronous function errors are returned directly to the runner. This test
does not exercise the asynchronous failure destination.
Evidence
Primary local report:
reports/load-c6bf5cd2857c411e86f44feb75c4b261.json.

Supporting evidence includes the supplied workload summary, per-case
results, Lambda logs, SQS queue counts, and independent EC2 group query.
Generated reports and raw logs remain outside version control.
Cost evidence and attribution
Billing review is pending. No Cost Explorer export, observed dollar amounts,
cost-allocation filters, or pricing calculations were supplied.

Measured workload counts are 12 invocation requests, four completed routed
findings, and eight ignored events. The routed path performs evidence writes
and SNS publication. Counts describe application behavior, not a billing invoice.

No incremental dollar cost or cost-per-event figure is claimed. Shared
account spending includes other projects, idle services, and previous tests.
It must not be divided by 12 to represent this workload's cost per event.

Before closing the cost checkpoint, record billing account scope, date range,
service totals, tag filters where available, data-check time, estimated-data
status, and attribution limitations. If access is unavailable, record the
observed access limitation and payer-account review status.
Limitations and remaining work
- Synthetic fixtures directly invoke Lambda and supply their own sample markers;
  they are not newly generated GuardDuty findings.
- Eight correctly ignored events validate an input boundary, not the accuracy
  of threat detection or a general false-positive rate.
- No saturation, sustained-load, or production-capacity claim is made.
- Persistent notification deduplication and partial-side-effect recovery
  remain outstanding.
- Concurrent response execution and changed-resource tests remain outstanding.
- Confirm workload email receipt and dashboard observations; complete billing
  review or document an actual access limitation.
- Final regression tests, Terraform checks, and the Session 8B commit were not
  included in the supplied results and are not claimed complete here.