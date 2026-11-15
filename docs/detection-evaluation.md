# Detection evaluation and analyst outcomes

`app.evaluate_detection` calls the existing `public_ssh_rules` classifier.
It does not duplicate detection logic, authorize responses, or label exposure as
compromise.

```sh
python -m unittest discover -s tests -v
python -m app.evaluate_detection --output detection-evaluation.json
```

The versioned synthetic development dataset covers public IPv4/IPv6 SSH,
all-protocol and port-range rules, private ingress, outbound rules, HTTPS,
UDP and empty rules. Each case has an explicit boolean ground-truth label.
Reports include TP/FP/TN/FN, accuracy, precision, recall, false-positive rate,
sample size and dataset digest. A classification mismatch exits 1.
Undefined denominators are null, not perfect scores.

Analyst review is a separate observation: `confirmed`, `dismissed` or
`pending`, with optional nonnegative `effort_seconds`.
All bundled reviews are pending; no analyst productivity or effort savings are
claimed. Record actual analyst outcomes without changing ground truth to match
the classifier. Supplied labels and reviews are self-attested.

Tests deliberately invert labels to verify that false positives and false
negatives remain visible. Empty datasets, duplicate IDs, nonboolean labels and
invalid measurements are rejected. The dedicated workflow runs on every pushed
branch and uploads evidence for 14 days.

These narrow development fixtures are not a production detection benchmark.
Reachability, compromise, real false-positive prevalence and human review time
require separate representative evidence.
