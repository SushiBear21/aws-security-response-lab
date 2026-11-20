"""Offline enterprise security/GitOps model; no boto3, credentials, or cloud calls."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GateDenied(ValueError):
    """A modeled security or change-control invariant was violated."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def check_architecture(model):
    """Defense-in-depth checks independent of the CI Rego policy."""
    errors = []
    accounts = model.get("accounts", {})
    if set(accounts) != {"management", "log_archive", "security_tooling", "workload"}:
        errors.append("four named account roles required")
    if len(set(accounts.values())) != 4 or any(
        not (isinstance(v, str) and len(v) == 12 and v.isdigit()) for v in accounts.values()
    ):
        errors.append("four unique 12-digit synthetic account identifiers required")
    if model.get("mode") != "synthetic_blueprint":
        errors.append("synthetic-only mode required")
    logging = model.get("logging", {})
    for field in ("organization_trail", "multi_region", "global_service_events", "log_file_validation"):
        if logging.get(field) is not True:
            errors.append("logging." + field + " must be true")
    if logging.get("destination_account") != "log_archive":
        errors.append("organization log destination must be log_archive")
    bucket = logging.get("bucket", {})
    for field in ("tls_required", "public_access_blocked", "versioning", "object_lock", "source_arn_condition"):
        if bucket.get(field) is not True:
            errors.append("logging.bucket." + field + " must be true")
    if bucket.get("encryption") != "aws:kms" or bucket.get("retention_days", 0) < 30:
        errors.append("central log encryption and 30-day minimum retention required")
    for section, field in (("guardduty", "delegated_admin"), ("security_hub_cspm", "delegated_admin"),
                           ("aws_config", "organization_aggregator_account")):
        if model.get(section, {}).get(field) != "security_tooling":
            errors.append(section + " delegation must be security_tooling")
    iam = model.get("iam", {}).get("cross_account_audit_role", {})
    if iam.get("trusted_account") != "security_tooling" or not iam.get("external_id_required"):
        errors.append("cross-account access must bind identity and external ID")
    if not iam.get("permission_boundary_required"):
        errors.append("permission boundary required")
    if any("*" in action for action in iam.get("allowed_actions", [])):
        errors.append("wildcard IAM action forbidden in audit role")
    response = model.get("response", {})
    if not response.get("human_approval_required") or not response.get("approval_exact_plan_digest"):
        errors.append("exact plan human approval required")
    flags = model.get("safeguards", {})
    if flags.get("aws_deployment_enabled") or flags.get("azure_in_scope") or flags.get("allowed_cloud_spend_usd") != 0:
        errors.append("cloud deployment/spend and Azure forbidden in simulation")
    return errors


def check_baseline(baseline):
    if set(baseline) != {"security_baseline"}:
        raise GateDenied("Unexpected Terraform inputs")
    record = baseline["security_baseline"]
    if any(record.get(key) is not True for key in (
        "organization_logging", "delegated_findings", "configuration_audit", "least_privilege_iam"
    )):
        raise GateDenied("Security baseline fails policy")
    if not isinstance(record.get("version"), str) or not record["version"]:
        raise GateDenied("Missing baseline version")


def initial_state():
    return {"generation": 0, "desired": None}


def make_plan(desired, current, revision, author, pr):
    check_baseline(desired)
    if not revision or not author or not pr:
        raise GateDenied("revision, author and PR reference required")
    plan = {
        "schema": 1, "mode": "synthetic_local_only",
        "revision": revision, "pr": pr, "author": author,
        "expected_generation": current["generation"],
        "before_sha256": digest(current["desired"]),
        "after_sha256": digest(desired),
        "desired": deepcopy(desired),
    }
    return plan


def approve(plan, reviewer, decision="APPROVED"):
    # Identity strings are synthetic fixtures; not independently authenticated.
    if not reviewer or reviewer == plan["author"]:
        raise GateDenied("Reviewer must differ from change author")
    return {
        "reviewer": reviewer, "decision": decision, "pr": plan["pr"],
        "revision": plan["revision"], "plan_sha256": digest(plan),
        "mode": "synthetic_fixture_not_real_github_review",
    }


def apply(plan, approval, state, expected_plan_sha256, expected_revision):
    # Apply is a local in-memory simulation, NEVER terraform apply or AWS APIs.
    if digest(plan) != expected_plan_sha256 or plan["revision"] != expected_revision:
        raise GateDenied("Exact saved-plan digest or revision mismatch")
    if approval is None or approval.get("decision") != "APPROVED":
        raise GateDenied("Explicit approval required")
    if approval.get("mode") != "synthetic_fixture_not_real_github_review":
        raise GateDenied("Unknown approval model")
    if approval.get("reviewer") in ("", None, plan["author"]):
        raise GateDenied("Independent reviewer identity required")
    for field, value in (("pr", plan["pr"]), ("revision", plan["revision"]),
                         ("plan_sha256", digest(plan))):
        if approval.get(field) != value:
            raise GateDenied("Approval not bound to reviewed plan: " + field)
    if state["generation"] != plan["expected_generation"] or digest(state["desired"]) != plan["before_sha256"]:
        raise GateDenied("Stale or replayed plan; current state has changed")
    check_baseline(plan["desired"])
    if digest(plan["desired"]) != plan["after_sha256"]:
        raise GateDenied("Desired config was modified after planning")
    updated = {"generation": state["generation"] + 1, "desired": deepcopy(plan["desired"])}
    if digest(updated["desired"]) != plan["after_sha256"]:
        raise GateDenied("Post-apply verification failed")
    return updated


def demo():
    """Simulate reviewed change, denied change, exact-plan apply and newly approved rollback."""
    original = load(ROOT / "terraform" / "baseline.tfvars.json")
    change = load(ROOT / "terraform" / "change.tfvars.json")
    denied = load(ROOT / "terraform" / "denied.tfvars.json")
    state = initial_state()
    baseline = make_plan(original, state, "synthetic-base-commit", "author-a", "PR-SYN-1")
    state = apply(baseline, approve(baseline, "reviewer-b"), state,
                  digest(baseline), baseline["revision"])
    change_plan = make_plan(change, state, "synthetic-change-commit", "author-a", "PR-SYN-2")
    denied_unapproved = False
    try:
        apply(change_plan, None, state, digest(change_plan), change_plan["revision"])
    except GateDenied:
        denied_unapproved = True
    denied_policy = False
    try:
        make_plan(denied, state, "synthetic-unsafe-commit", "author-a", "PR-SYN-3")
    except GateDenied:
        denied_policy = True
    before = state
    state = apply(change_plan, approve(change_plan, "reviewer-c"), state,
                  digest(change_plan), change_plan["revision"])
    verified_change = digest(state["desired"]) == digest(change)
    denied_replay = False
    try:
        apply(change_plan, approve(change_plan, "reviewer-c"), state,
              digest(change_plan), change_plan["revision"])
    except GateDenied:
        denied_replay = True
    rollback = make_plan(original, state, "synthetic-rollback-commit", "author-a", "PR-SYN-4")
    state = apply(rollback, approve(rollback, "reviewer-d"), state,
                  digest(rollback), rollback["revision"])
    verified_rollback = digest(state["desired"]) == digest(before["desired"])
    return {
        "mode": "synthetic_local_only", "external_review_verified": False,
        "reviewed_revision": change_plan["revision"], "reviewed_pr": change_plan["pr"],
        "plan_sha256": digest(change_plan), "baseline_sha256": digest(original),
        "rollback_plan_sha256": digest(rollback), "revision_after_rollback": rollback["revision"],
        "denied_unapproved_apply": denied_unapproved, "denied_noncompliant_policy": denied_policy,
        "denied_replay": denied_replay, "post_apply_verified": verified_change,
        "rollback_verified": verified_rollback, "final_generation": state["generation"],
        "cloud_api_calls": 0,
    }


if __name__ == "__main__":
    print(json.dumps(demo(), sort_keys=True, indent=2))
