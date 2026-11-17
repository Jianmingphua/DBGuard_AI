"""Prove an ordered set of fixes together in one disposable sandbox; test a fix on its own only
when it fails there (Melvin's ruling of 12 Nov 2026: combined first)."""

import copy
import io
import json
import hashlib
import uuid
import zipfile
from html import escape
from app.services.fix_unit_render import render_action
from app.services.spec_engine.policy import approval_text
from .planning import SANDBOX_LIMITS, change_keys, fix_phase, order_key, recommend_order
from .provenance import reconstruct, reconstruction_plan, signature
from .shared import ContractError, blocking_gaps, digest, is_regression
from .review_bundle import (OBJECT_REHEARSAL_TEXT, PRELOAD_README, TLS_README, build_combined_fix_files,
                            build_review_bundle,
                            is_fixture, object_fingerprint, stage_screenshots, strip_screenshot_data)
from .workflow import in_transaction, health_queries, _normalised
from . import catalog_skeleton
from .runtime import SandboxStartError
from . import package_assets
from . import client_impact
from . import history
from . import terminal_capture


def _object_fixes():
    from . import object_fixes
    return object_fixes


def request_fix_id(request) -> str:
    """Batch identity: the object fix id, else the setting fix id of the control."""
    fix_id = getattr(request, "object_fix_id", None)
    if fix_id:
        return fix_id
    return "control:" + request.control_id


def _request_matches(request, result) -> bool:
    fix_id = getattr(request, "object_fix_id", None)
    if is_object(result):
        return fix_id == result["fix_unit"]["fix_id"]
    return not fix_id and request.control_id == result["fix_unit"]["spec_id"]


def is_object(result) -> bool:
    return result.get("kind") == "object"


def is_catalog(result) -> bool:
    """W2B: a catalog-linked setting fix (3.2, 5.6, 6.10)."""
    return result.get("kind") == "catalog_setting"


def _catalog_scopes(engine, snapshot, requests) -> dict:
    """control_id -> evidence-derived scope for each catalog-linked request."""
    from . import catalog_fixes as cf
    return {r.control_id: cf.catalog_fix_scope(engine, snapshot, r.control_id) for r in requests
            if not getattr(r, "object_fix_id", None) and cf.is_catalog_fix(engine, r.control_id)}


def _catalog_step(engine, runtime, plan, scope, result, previous, applied_catalog, skeleton, templates, pending):
    """Apply one catalog-linked fix in the combined sandbox and verify it with its catalog check.

    The fix is re-derived from the combined sandbox's own collection (W2B rulings round 3),
    so a later preload fix keeps the libraries an earlier one added: its prior is the
    earlier fix's result, and its rollback restores exactly that list. ``pending`` keeps the
    re-derived rollback before any SQL runs, so a failed step is still rolled back exactly.
    """
    from . import catalog_fixes as cf
    template, list_template = templates
    prior = engine.assess(previous)
    scope = cf.catalog_fix_scope(engine, previous, result["fix_unit"]["spec_id"], prior)
    uses_list = any(c["template"] == cf.LIST_TEMPLATE for c in scope["changes"])
    fix = cf.build_fix(scope, template.version, list_template.version if uses_list else None)
    rendered = cf.rendered_statements(template, scope, list_template if uses_list else None)
    pending[fix["fix_id"]] = {"rollback_sql": cf.rollback_sql(fix), "fix_unit": fix}
    for sql in rendered:
        runtime.sql(sql)
    expected = {n: r["setting"] for n, r in signature(previous, plan["names"])["settings"].items()}
    expected.update({c["param"]: c["expected_value"] for c in fix["changes"]})
    runtime.activate(expected)
    after = engine.collect(runtime)
    report = engine.assess(after)
    regressions = [sid for sid, f in prior["findings"].items()
                   if is_regression(f["status"], report["findings"][sid]["status"])
                   or sid in engine.gapped_settings(report["findings"])]
    regressions += cf.catalog_regressions(engine, prior, report, [c["param"] for c in fix["changes"]], fix["spec_id"])
    checks = cf.functional_checks(runtime, fix, "AFTER COMBINED FIX " + fix["fix_id"])
    passing = [cf.proof(engine, s["spec"], after)["result"] == "PASS" for s in applied_catalog + [scope]]
    tls = cf.tls_evidence(runtime) if scope["tls"] else None
    if (not all(passing) or regressions or blocking_gaps(after) or not checks["passed"] or not runtime.health()
            or (tls is not None and not cf.tls_fixed(tls))
            or (skeleton and catalog_skeleton.fingerprints(after, skeleton)
                != catalog_skeleton.fingerprints(previous, skeleton))):
        raise ContractError("Combined target, regression or functional gate failed")
    step = {"fix_id": fix["fix_id"], "before": previous, "after": after, "assessment": report,
            "functional_checks": checks, "catalog_proof": cf.proof(engine, scope["spec"], after),
            "fix_unit": fix, "rendered_apply_statements": rendered, "rendered_rollback_sql": cf.rollback_sql(fix),
            "chained": fix != result["fix_unit"]}
    if tls is not None:
        step["tls_after"] = tls
    return step


def _catalog_rollback(engine, runtime, plan, scope, result, expected_snapshot, skeleton, pending) -> bool:
    from . import catalog_fixes as cf
    runtime.sql(pending[result["fix_unit"]["fix_id"]]["rollback_sql"])
    runtime.activate({n: r["setting"] for n, r in signature(expected_snapshot, plan["names"])["settings"].items()})
    restored = engine.collect(runtime)
    names = list(dict.fromkeys(result["names"] + [c["param"] for c in pending[result["fix_unit"]["fix_id"]]["fix_unit"]["changes"]]))
    return bool(
        signature(restored, plan["names"]) == signature(expected_snapshot, plan["names"])
        and cf.catalog_signature(restored, names) == cf.catalog_signature(expected_snapshot, names)
        and engine.assess(restored)["findings"] == engine.assess(expected_snapshot)["findings"]
        and cf.proof(engine, scope["spec"], restored) == cf.proof(engine, scope["spec"], expected_snapshot)
        and not blocking_gaps(restored) and runtime.health()
        and _objects_unchanged(skeleton, restored, expected_snapshot))


def object_proposal(engine, snapshot, request) -> dict:
    proposal = _object_fixes().resolve(engine, snapshot, engine.policy_pin, request.object_fix_id)
    if not isinstance(proposal, dict) or proposal.get("fix_id") != request.object_fix_id:
        raise ContractError("Selected object fix is not offered for this evidence")
    return proposal


def _attributes(proposal) -> set:
    """The (object, attribute) pairs one object fix changes."""
    key = catalog_skeleton.target_key(proposal)
    fix_type, target = proposal["fix_type"], proposal["target"]
    if fix_type == "role_connection_limit":
        return {(key, "connection_limit")}
    if fix_type == "role_drop_attribute":
        return {(key, "attribute:" + str(target["attribute"]))}
    if fix_type == "role_nologin":
        return {(key, "login")}
    if fix_type == "function_security_invoker":
        return {(key, "security")}
    if fix_type == "function_revoke_public_execute":
        return {(key, "acl:PUBLIC")}
    if fix_type == "table_revoke_dml":
        # One pair per revoked privilege: INSERT and UPDATE for the same grantee are
        # separate attributes (the engine splits proposals by grant option).
        return {(key, "acl:" + str(target["grantee"]) + ":" + privilege) for privilege in target["privileges"]}
    raise ContractError("Unsupported object fix type")


def object_conflicts(proposals) -> None:
    seen = set()
    for proposal in proposals:
        pairs = _attributes(proposal)
        if pairs & seen:
            raise ContractError("Two selected fixes change the same object attribute")
        seen |= pairs


def _objects_unchanged(skeleton, current, expected, except_key=None) -> bool:
    if not skeleton:
        return True
    now = catalog_skeleton.fingerprints(current, skeleton)
    want = catalog_skeleton.fingerprints(expected, skeleton)
    return all(now[k] == want[k] for k in want if k != except_key) and (
        except_key is None or _normalised(now.get(except_key)) == _normalised(want.get(except_key)))


def _object_step(engine, runtime, fixes, plan, skeleton, result, previous, applied_objects):
    """Apply one object fix (one transaction) in the combined sandbox and verify it."""
    proposal, fix = result["proposal"], result["fix_unit"]
    key = catalog_skeleton.target_key(proposal)
    runtime.sql(in_transaction(fix["apply"]["statements"]))
    after = engine.collect(runtime)
    report = engine.assess(after)
    prior = engine.assess(previous)
    regressions = [sid for sid, f in prior["findings"].items()
                   if is_regression(f["status"], report["findings"][sid]["status"])
                   or sid in engine.gapped_settings(report["findings"])]
    checks = health_queries(runtime, "AFTER COMBINED FIX " + fix["fix_id"])
    before_prints = catalog_skeleton.fingerprints(previous, skeleton)
    after_prints = catalog_skeleton.fingerprints(after, skeleton)
    others = sorted(k for k in before_prints if k != key and after_prints[k] != before_prints[k])
    # Every object fix applied so far still holds (per-object predicates).
    holding = all(fixes.predicate(r["proposal"], after) for r in applied_objects)
    if (not fixes.predicate(proposal, after) or not holding or regressions or others
            or blocking_gaps(after) or not checks["passed"] or not runtime.health()
            or signature(after, plan["names"]) != signature(previous, plan["names"])):
        raise ContractError("Combined target, regression or functional gate failed")
    return {"fix_id": fix["fix_id"], "before": previous, "after": after,
            "assessment": report, "functional_checks": checks}


def _object_rollback(engine, runtime, fixes, plan, skeleton, result, expected_snapshot):
    proposal = result["proposal"]
    runtime.sql(in_transaction(result["fix_unit"]["rollback"]["statements"]))
    restored = engine.collect(runtime)
    return bool(
        fixes.object_signature(proposal, restored) == fixes.object_signature(proposal, expected_snapshot)
        and signature(restored, plan["names"]) == signature(expected_snapshot, plan["names"])
        and engine.assess(restored)["findings"] == engine.assess(expected_snapshot)["findings"]
        and not blocking_gaps(restored)
        and _objects_unchanged(skeleton, restored, expected_snapshot, catalog_skeleton.target_key(proposal))
        and runtime.health())


def _combined_targets(results):
    """Every changed setting and object of the batch, from the server-side fix units and
    evidence-derived proposals; None (no terminal picture) if anything is malformed."""
    try:
        return terminal_capture.merge_targets(
            terminal_capture.setting_targets(
                [r["fix_unit"]["apply"]["param"] for r in results if not is_object(r) and not is_catalog(r)]
                + [c["param"] for r in results if is_catalog(r) for c in r["fix_unit"]["changes"]]),
            terminal_capture.object_targets([r["proposal"] for r in results if is_object(r)]))
    except Exception:
        return None




# ---------------------------------------------------------------------------
# Batches (Melvin's rulings, 10 Nov): any number of offered fixes; phase 1 (no restart)
# then phase 2 (one joint restart); a failing fix is left out and the rest continue.
# ---------------------------------------------------------------------------

MAX_COMBINED_RETRIES = 3
PASSED, FAILED, NOT_ELIGIBLE = "PASSED", "FAILED", "NOT_ELIGIBLE"


class _Emit:
    """Plain-English progress events for the caller's callback; never changes a verdict."""

    def __init__(self, callback):
        self.callback = callback

    def __call__(self, **event):
        if self.callback is None:
            return
        try:
            self.callback(event)
        except Exception:
            pass


def _phase(result) -> int:
    return fix_phase(result["risk_review"])


def _fid(result) -> str:
    return result["fix_unit"]["fix_id"]


def _name(review, fallback) -> str:
    """The short name a DBA recognises: the setting, else the fix id."""
    if not review:
        return fallback
    return review.get("setting") or review.get("fix_id") or fallback


def _label(review, fallback) -> str:
    risk = (review or {}).get("operational_risk")
    return _name(review, fallback) + (f" ({risk.replace('_', ' ')} risk)" if risk else "")


def _exception_reason(exc) -> str:
    """A reason safe to show: our own contract messages, an HTTP detail, else the error type."""
    detail = getattr(exc, "detail", None)
    if isinstance(detail, str):
        return detail
    if isinstance(exc, ContractError):
        return str(exc)
    return f"The sandbox test stopped with an internal error ({type(exc).__name__})"


def _result_reason(result) -> str:
    attempts = result.get("attempts") or []
    last = attempts[-1] if attempts else {}
    for value in (result.get("reason"), last.get("error"), last.get("apply_or_assessment_error")):
        if isinstance(value, str) and value:
            return value
    if result.get("status") == "CLEANUP_FAILED":
        return "Its disposable sandbox could not be removed and verified as removed"
    if last and last.get("rollback_verified") is False:
        return "Its rollback could not be verified"
    return f"Its own sandbox test ended {result.get('status', 'without a result')}"


def _profile(engine, snapshot, request, scopes, proposals):
    """Planning-time risk entry (no model, no template pin) used for conflicts and labels."""
    from .planning import risk_review
    from .workflow import object_risk_review
    from . import catalog_fixes as cf
    key = request_fix_id(request)
    if key in proposals:
        return object_risk_review(proposals[key])
    if request.control_id in scopes:
        return cf.catalog_risk_review(engine, snapshot, request.control_id, scope=scopes[request.control_id])
    return risk_review(engine, snapshot, request.control_id)


def _conflict_keys(profile, proposal) -> dict:
    """change key -> plain description, for the conflict rule."""
    if proposal is not None:
        # Per (object, attribute), as object_conflicts: the same change offered under two
        # controls (NOSUPERUSER for 4.3 and 4.9) is one attribute.
        return {("attribute",) + pair: "object attribute (" + pair[1].split(":", 1)[-1] + " of "
                + pair[0].replace("\x1f", ".").replace(":", " ", 1) + ")" for pair in _attributes(proposal)}
    return {key: f"setting {key[1]}" for key in change_keys(profile)}


def plan_batch(requests, service, requested_order=None, fix_all=False) -> dict:
    """Validate a batch before any container: at least one fix, every fix offered by this
    snapshot's fix plan (service.validate_handoff / object resolve), each at most once.

    Conflicts (two fixes changing the same setting, except the chainable preload list, or
    the same object attribute) refuse the batch; in a fix-all batch the first-ordered
    (lower-risk) fix is kept and the other is NOT_ELIGIBLE with the reason.
    """
    if not requests:
        raise ContractError("Select at least one fix")
    first = requests[0]
    if any(
        r.snapshot != first.snapshot or r.spec_set_hash != first.spec_set_hash
        or r.policy_profile_sha256 != first.policy_profile_sha256
        for r in requests
    ):
        raise ContractError("Batch fixes must share the same snapshot, exact specs and policy profile")
    keys = [request_fix_id(r) for r in requests]
    if len(set(keys)) != len(keys):
        raise ContractError("Duplicate fixes in batch")
    if requested_order is not None and len(set(requested_order)) != len(requested_order):
        raise ContractError("Selected order must contain every fix exactly once")
    engine = service.validate_handoff(first)
    # Object fixes are re-derived from the shared evidence before anything runs.
    proposals = {request_fix_id(r): object_proposal(engine, first.snapshot, r) for r in requests
                 if getattr(r, "object_fix_id", None)}
    if not fix_all:
        object_conflicts(list(proposals.values()))
    scopes = _catalog_scopes(engine, first.snapshot, requests)
    profiles, not_eligible = {}, {}
    for r in requests:
        try:
            profiles[request_fix_id(r)] = _profile(engine, first.snapshot, r, scopes, proposals)
        except Exception:
            if fix_all:
                raise
            profiles[request_fix_id(r)] = None  # labels only; the run itself re-validates
    if fix_all:
        if requested_order is not None:
            raise ContractError("A fix-all batch uses the recommended order")
        taken = {}
        for r in sorted(requests, key=lambda r: order_key(profiles[request_fix_id(r)])):
            key = request_fix_id(r)
            mine = _conflict_keys(profiles[key], proposals.get(key))
            clash = next((k for k in mine if k in taken), None)
            if clash is not None:
                not_eligible[key] = (f"Not tested: it changes the same {mine[clash]} as {taken[clash]}, which "
                                     "comes first (lower risk or earlier in the order). Test it in a separate batch.")
                continue
            taken.update({k: profiles[key]["fix_id"] for k in mine})
    eligible = [r for r in requests if request_fix_id(r) not in not_eligible]
    # Approved templates for each catalog fix (the list template for a preload change).
    catalog_templates = {r.control_id: (service.resolve_template(r),
                                        service.resolve_template(r, r.list_template_ref)
                                        if getattr(r, "list_template_ref", None) is not None else None)
                         for r in eligible if r.control_id in scopes}
    return {"requests": list(requests), "eligible": eligible, "engine": engine, "first": first,
            "scopes": scopes, "catalog_templates": catalog_templates, "profiles": profiles,
            "not_eligible": not_eligible, "requested_order": requested_order, "fix_all": fix_all}


def _fix_id_for(plan, request) -> str:
    profile = plan["profiles"].get(request_fix_id(request))
    return (profile or {}).get("fix_id") or request_fix_id(request)


def _setting_step(engine, runtime, plan, result, previous, skeleton, defer=False):
    """Apply one reviewed setting fix in the combined sandbox and verify it.

    ``defer``: its prerequisite (logging_collector) is a phase 2 fix of this batch, so the
    control's own PASS is checked after the joint restart (FIX_DEPENDENCIES ruling); the
    effective value, health, regressions and gaps are still checked now.
    """
    from .evidence_capture import verify_runtime
    from .workflow import setting_catalog_regressions
    fix = result["fix_unit"]
    runtime.sql(result["rendered_apply_sql"])
    expected = {n: r["setting"] for n, r in signature(previous, plan["names"])["settings"].items()}
    expected[fix["apply"]["param"]] = fix["apply"]["value"]
    runtime.activate(expected)
    after = engine.collect(runtime)
    report = engine.assess(after)
    prior = engine.assess(previous)
    regressions = [sid for sid, f in prior["findings"].items()
                   if is_regression(f["status"], report["findings"][sid]["status"])]
    regressions += setting_catalog_regressions(engine, prior, report, fix["apply"]["param"], fix["spec_id"])
    checks = verify_runtime(runtime, fix["spec_id"], fix["apply"]["param"], fix["apply"]["value"],
                            "AFTER COMBINED FIX " + fix["fix_id"])
    if (
        (not defer and report["findings"][fix["spec_id"]]["status"] != "PASS")
        or regressions
        or blocking_gaps(after)
        or not checks["passed"]
        or (skeleton and catalog_skeleton.fingerprints(after, skeleton)
            != catalog_skeleton.fingerprints(previous, skeleton))
    ):
        raise ContractError("Combined target, regression or functional gate failed")
    step = {"fix_id": fix["fix_id"], "before": previous, "after": after, "assessment": report,
            "functional_checks": checks}
    if defer:
        step["verification"] = "AFTER_RESTART"
    return step


def _changed(result) -> set:
    """The settings one setting or catalog-linked fix writes."""
    unit = result["fix_unit"]
    return {c["param"] for c in unit["changes"]} if "changes" in unit else {unit["apply"]["param"]}


def restart_rounds(phase2) -> list:
    """Restart fixes grouped so that no two fixes in a round write the same setting.

    Normally one round: every restart fix is written, then the sandbox restarts ONCE
    (Melvin, 10 Nov). A fix that builds on a setting an earlier restart fix of this batch
    already changed (3.2 and 5.6 both append to shared_preload_libraries) goes to the next
    round: W2B rulings round 3 derive it from the sandbox's own collection after the
    earlier fix, which exists only after that fix's restart.
    """
    rounds, written = [], []
    for result in phase2:
        index = max((i + 1 for i, names in enumerate(written) if names & _changed(result)), default=0)
        if index == len(rounds):
            rounds.append([])
            written.append(set())
        rounds[index].append(result)
        written[index] |= _changed(result)
    return rounds


def execution_order(results) -> list:
    """Phase 1 in the given order, then the restart fixes round by round."""
    phase2 = [r for r in results if _phase(r) == 2]
    return [r for r in results if _phase(r) == 1] + [r for group in restart_rounds(phase2) for r in group]


def _restart_round(ctx, runtime, record, state, group, before, deferred, applied, applied_catalog, emit):
    """Write every restart fix of one round, restart the sandbox once (runtime.activate
    restarts only for the reviewed restart settings), then check each of them, the fixes
    whose check waited for this restart, and the joint gate. Returns the new state."""
    from . import catalog_fixes as cf
    from .evidence_capture import verify_runtime
    from .workflow import setting_catalog_regressions
    engine, plan, skeleton, pending = ctx["engine"], ctx["plan"], ctx["skeleton"], ctx["pending"]
    number = len(state["rounds"]) + 1
    state["rounds"].append({"before": before, "fixes": group})
    expected = {n: r["setting"] for n, r in signature(before, plan["names"])["settings"].items()}
    prior = engine.assess(before)
    written = []
    for index, result in enumerate(group, 1):
        state["current"] = _fid(result)
        emit(kind="combined_write", phase=2, step="apply", fix_id=_fid(result),
             text=f"{ctx['title']}, phase 2: writing restart fix {index} of {len(group)}: "
                  f"{_label(result['risk_review'], _fid(result))}…")
        applied.append(result)  # marked before SQL so a partial apply is also rolled back
        if is_catalog(result):
            # Re-derived from this sandbox's own collection (W2B rulings round 3).
            spec_id = result["fix_unit"]["spec_id"]
            template, list_template = ctx["catalog_templates"][spec_id]
            scope = cf.catalog_fix_scope(engine, before, spec_id, prior)
            uses_list = any(c["template"] == cf.LIST_TEMPLATE for c in scope["changes"])
            fix = cf.build_fix(scope, template.version, list_template.version if uses_list else None)
            rendered = cf.rendered_statements(template, scope, list_template if uses_list else None)
            pending[fix["fix_id"]] = {"rollback_sql": cf.rollback_sql(fix), "fix_unit": fix}
            for sql in rendered:
                runtime.sql(sql)
            expected.update({c["param"]: c["expected_value"] for c in fix["changes"]})
            written.append((result, fix, rendered, scope))
        else:
            runtime.sql(result["rendered_apply_sql"])
            expected[result["fix_unit"]["apply"]["param"]] = result["fix_unit"]["apply"]["value"]
            written.append((result, None, None, None))
    state.update(current=None, stage="restart")
    emit(kind="restart", phase=2, step="restart",
         text=(f"{ctx['title']}, phase 2: restarting the sandbox database once for {len(group)} restart "
               f"fix{'es' if len(group) != 1 else ''}…" if number == 1 else
               f"{ctx['title']}, phase 2: restarting the sandbox database again for "
               f"{', '.join(_fid(r) for r in group)}, which builds on a setting an earlier restart fix changed…"))
    runtime.activate(expected)
    record["restarts"] = record.get("restarts", 0) + 1
    state["stage"] = "phase 2"
    after = engine.collect(runtime)
    report = engine.assess(after)
    for index, (result, fix, rendered, scope) in enumerate(written, 1):
        fid = _fid(result)
        state["current"] = fid
        emit(kind="combined_check", phase=2, step="verify", fix_id=fid,
             text=f"{ctx['title']}, phase 2: checking restart fix {index} of {len(written)} after the restart: "
                  f"{_name(result['risk_review'], fid)}…")
        phase = "AFTER COMBINED RESTART " + fid
        if fix is None:
            unit = result["fix_unit"]
            checks = verify_runtime(runtime, unit["spec_id"], unit["apply"]["param"], unit["apply"]["value"], phase)
            own = setting_catalog_regressions(engine, prior, report, unit["apply"]["param"], unit["spec_id"])
            ok = report["findings"][unit["spec_id"]]["status"] == "PASS" and not own and checks["passed"]
            step = {"fix_id": fid, "before": before, "after": after, "assessment": report, "functional_checks": checks}
        else:
            own = cf.catalog_regressions(engine, prior, report, [c["param"] for c in fix["changes"]], fix["spec_id"])
            checks = cf.functional_checks(runtime, fix, phase)
            catalog_proof = cf.proof(engine, scope["spec"], after)
            ok = catalog_proof["result"] == "PASS" and not own and checks["passed"]
            step = {"fix_id": fid, "before": before, "after": after, "assessment": report, "functional_checks": checks,
                    "catalog_proof": catalog_proof, "fix_unit": fix, "rendered_apply_statements": rendered,
                    "rendered_rollback_sql": cf.rollback_sql(fix), "chained": fix != result["fix_unit"]}
        if not ok:
            raise ContractError("Combined target, regression or functional gate failed after the restart")
        step.update(phase=2, joint_restart=True, restart_round=number)
        record["steps"].append(step)
    restarted = {_fid(r) for r in applied if _phase(r) == 2}
    for step, result in deferred:
        # FIX_DEPENDENCIES ruling: verified once its prerequisite (logging_collector) is on.
        unit, fid = result["fix_unit"], _fid(result)
        waiting = set(result["risk_review"].get("dependencies") or []) & ctx["phase2_ids"]
        if "verified_after_restart" in step or not waiting <= restarted:
            continue
        state["current"] = fid
        emit(kind="deferred_check", phase=2, step="verify", fix_id=fid,
             text=f"{ctx['title']}, phase 2: checking {_name(result['risk_review'], fid)} again now that "
                  "logging_collector is on…")
        checks = verify_runtime(runtime, unit["spec_id"], unit["apply"]["param"], unit["apply"]["value"],
                                "AFTER COMBINED RESTART " + fid)
        if report["findings"][unit["spec_id"]]["status"] != "PASS" or not checks["passed"]:
            raise ContractError("Combined target check failed after the restart that switched logging_collector on")
        step["verified_after_restart"] = {"status": report["findings"][unit["spec_id"]]["status"],
                                          "functional_checks": checks}
    # The joint gate cannot name one fix; it is attributed to the round's last (highest-risk) fix.
    state["current"] = _fid(group[-1])
    regressions = [sid for sid, f in prior["findings"].items()
                   if is_regression(f["status"], report["findings"][sid]["status"])
                   or sid in engine.gapped_settings(report["findings"])]
    applied_catalog += [w[3] for w in written if w[3] is not None]
    objects = [r for r in applied if is_object(r)]
    if (regressions or blocking_gaps(after) or not runtime.health()
            or not all(cf.proof(engine, s["spec"], after)["result"] == "PASS" for s in applied_catalog)
            or (objects and not all(ctx["fixes"].predicate(r["proposal"], after) for r in objects))
            or (skeleton and catalog_skeleton.fingerprints(after, skeleton)
                != catalog_skeleton.fingerprints(before, skeleton))):
        raise ContractError("Combined regression or functional gate failed after the joint restart")
    state["current"] = None
    return after


def _joint_rollback(ctx, runtime, record, before, group):
    """Roll back the restart fixes of one round, restart once, and verify the exact state
    the sandbox had before that round."""
    from . import catalog_fixes as cf
    engine, plan, pending = ctx["engine"], ctx["plan"], ctx["pending"]
    for result in reversed(group):
        if is_catalog(result):
            if _fid(result) in pending:
                runtime.sql(pending[_fid(result)]["rollback_sql"])
        else:
            runtime.sql(result["rendered_rollback_sql"])
    runtime.activate({n: r["setting"] for n, r in signature(before, plan["names"])["settings"].items()})
    restored = engine.collect(runtime)
    catalog = [r for r in group if is_catalog(r) and _fid(r) in pending]
    names = list(dict.fromkeys(n for r in catalog for n in
                               r["names"] + [c["param"] for c in pending[_fid(r)]["fix_unit"]["changes"]]))
    specs = [ctx["scopes"][r["fix_unit"]["spec_id"]]["spec"] for r in catalog]
    ok = bool(
        signature(restored, plan["names"]) == signature(before, plan["names"])
        and (not names or cf.catalog_signature(restored, names) == cf.catalog_signature(before, names))
        and engine.assess(restored)["findings"] == engine.assess(before)["findings"]
        and all(cf.proof(engine, spec, restored) == cf.proof(engine, spec, before) for spec in specs)
        and not blocking_gaps(restored) and runtime.health()
        and _objects_unchanged(ctx["skeleton"], restored, before))
    for result in reversed(group):
        record["rollback"].append({"fix_id": _fid(result), "verified": ok, "joint_restart": True})
    if not ok:
        raise ContractError("Combined exact rollback failed")


def _combined_attempt(batch, service, results, emit, attempt):
    """One disposable sandbox: phase 1 fixes one at a time, phase 2 with one restart,
    then an exact reverse rollback. Returns the combined record; ``failed_fix_id`` names
    the fix whose step failed, ``hard_failure`` marks a failure that must not be retried
    (baseline, rollback or cleanup)."""
    from . import catalog_fixes as cf
    engine, first = batch["engine"], batch["first"]
    scopes = {r["fix_unit"]["spec_id"]: batch["scopes"][r["fix_unit"]["spec_id"]] for r in results if is_catalog(r)}
    title = "Combined test" + (f" (retry {attempt - 1} of {MAX_COMBINED_RETRIES})" if attempt > 1 else "")
    phase1 = [r for r in results if _phase(r) == 1]
    phase2 = [r for r in results if _phase(r) == 2]
    phase2_ids = {_fid(r) for r in phase2}
    runtime = service.runtime_factory()
    extra = [n for scope in scopes.values() for n in cf.reconstruction_names(engine, first.snapshot, scope)]
    plan = (reconstruction_plan(first.snapshot, engine.specs, list(dict.fromkeys(extra))) if extra
            else reconstruction_plan(first.snapshot, engine.specs))
    record = {"status": "FAILED", "steps": [], "rollback": [], "run_id": runtime.run_id, "attempt": attempt,
              "phases": {"1": [_fid(r) for r in phase1], "2": [_fid(r) for r in phase2]}}
    emit(kind="combined_start", count=len(results), attempt=attempt, phase="combined", step="start",
         text=f"{title}: starting one disposable sandbox for {len(results)} "
              f"fix{'es' if len(results) != 1 else ''} ({len(phase1)} without restart, {len(phase2)} with restart)…")
    # Task 2: three terminal screenshots for the whole combined test (no-op unless terminal mode).
    terminal_capture.begin(record)
    shots = _combined_targets(results) if "terminal_evidence" in record else None
    applied = []
    objects = [r for r in results if is_object(r)]
    ctx = {"engine": engine, "plan": plan, "skeleton": None, "pending": {}, "scopes": scopes, "title": title,
           "catalog_templates": batch["catalog_templates"], "fixes": _object_fixes() if objects else None,
           "phase2_ids": phase2_ids}
    fixes = ctx["fixes"]
    baseline = None  # the combined sandbox's own first collection (stand-in included)
    state = {"current": None, "stage": "baseline", "rounds": []}  # rounds: [{"before", "fixes"}]
    try:
        runtime.start()
        reconstruct(runtime, plan)
        if any(scope["tls"] for scope in scopes.values()):
            cf.enable_sandbox_tls(runtime, plan)
        if objects:
            # One stand-in holding every object target of the batch.
            ctx["skeleton"] = catalog_skeleton.build(runtime, first.snapshot, [r["proposal"] for r in objects])
            record["skeleton"] = ctx["skeleton"]
        skeleton = ctx["skeleton"]
        before = engine.collect(runtime)
        baseline = before
        if (
            signature(before, plan["names"]) != plan["signature"]
            or engine.assess(before)["findings"]
            != engine.assess(first.snapshot)["findings"]
        ):
            raise ContractError("Combined baseline reproduction differs")
        for result in results:
            if is_catalog(result):
                scope = scopes[result["fix_unit"]["spec_id"]]
                if (cf.proof(engine, scope["spec"], before)["result"] != "FAIL"
                        or cf.catalog_signature(before, result["names"])
                        != cf.catalog_signature(first.snapshot, result["names"])):
                    raise ContractError("Combined baseline does not reproduce " + _fid(result))
        for result in objects:
            proposal = result["proposal"]
            if (not fixes.prior_holds(proposal, before) or fixes.predicate(proposal, before)
                    or fixes.object_signature(proposal, before) != result["source_object_signature"]):
                raise ContractError("Combined stand-in does not reproduce " + proposal["fix_id"])
        terminal_capture.stage(record, runtime, "before", shots, "combined")
        previous = before
        state["stage"] = "phase 1"
        deferred = []
        for index, result in enumerate(phase1, 1):
            state["current"] = _fid(result)
            emit(kind="combined_step", phase=1, step="apply", fix_id=_fid(result),
                 text=f"{title}, phase 1 (no restart): applying {index} of {len(phase1)}: "
                      f"{_label(result['risk_review'], _fid(result))}…")
            # Mark before SQL so a partial apply is also rolled back.
            applied.append(result)
            if is_object(result):
                step = _object_step(engine, runtime, fixes, plan, skeleton, result, previous,
                                    [r for r in applied if is_object(r)])
            elif is_catalog(result):
                applied_catalog = [scopes[r["fix_unit"]["spec_id"]] for r in applied[:-1] if is_catalog(r)]
                step = _catalog_step(engine, runtime, plan, scopes[result["fix_unit"]["spec_id"]], result, previous,
                                     applied_catalog, skeleton, batch["catalog_templates"][result["fix_unit"]["spec_id"]],
                                     ctx["pending"])
            else:
                defer = bool(set(result["risk_review"].get("dependencies") or []) & phase2_ids)
                step = _setting_step(engine, runtime, plan, result, previous, skeleton, defer)
                if defer:
                    deferred.append((step, result))
            step["phase"] = 1
            record["steps"].append(step)
            previous = step["after"]
        applied_catalog = [scopes[r["fix_unit"]["spec_id"]] for r in applied if is_catalog(r)]
        for group in restart_rounds(phase2):
            state["stage"] = "phase 2"
            previous = _restart_round(ctx, runtime, record, state, group, previous, deferred, applied,
                                      applied_catalog, emit)
        terminal_capture.stage(record, runtime, "after", shots, "combined")
        record["status"] = "VERIFIED"
    except Exception as exc:
        record["reason"] = str(exc)
        record["status"] = "FAILED"
        if state["stage"] == "restart" and state["rounds"] and isinstance(exc, SandboxStartError):
            # PostgreSQL did not come back after the round's joint restart. Which fix of the
            # round caused it is not known here: execute_batch tests each of them on its own
            # and leaves out those failing alone (or the whole round if none does). The copy
            # cannot be undone without a running server; it is discarded and its removal
            # verified instead (12 Nov fix).
            round_ids = [_fid(r) for r in state["rounds"][-1]["fixes"]]
            record.update(failed_fix_id=round_ids[-1], failed_fix_ids=round_ids, failed_stage="restart",
                          start_failed=True)
        else:
            if state["stage"] == "restart" and state["rounds"]:
                # The joint restart failed after the server came back: the round's last fix.
                state["current"] = _fid(state["rounds"][-1]["fixes"][-1])
            if state["stage"] != "baseline" and state["current"]:
                record.update(failed_fix_id=state["current"], failed_stage=state["stage"])
    finally:
        try:
            if record.get("start_failed"):
                # Nothing can be undone on a server that is not running. No undo is claimed:
                # the copy is thrown away, and only its verified removal counts. The fixes
                # still in the batch get their undo proven in the retry.
                record["rollback_skipped"] = ("PostgreSQL did not start after the restart, so the copy was "
                                              "discarded instead of undone; its removal is verified below.")
                emit(kind="rollback", phase="rollback", step="rollback",
                     text=f"{title}: PostgreSQL did not start after the restart; discarding this copy…")
                applied = []
            if applied:
                emit(kind="rollback", phase="rollback", step="rollback",
                     text=f"{title}: undoing all fixes and checking the copy is back as before…")
            applied1 = [r for r in applied if _phase(r) == 1]
            for group in reversed(state["rounds"]):
                done = [r for r in group["fixes"] if any(r is a for a in applied)]
                if done:
                    _joint_rollback(ctx, runtime, record, group["before"], done)
            steps1 = [s for s in record["steps"] if s.get("phase") == 1]
            for result in reversed(applied1):
                # Desired baseline is the state immediately before this fix.
                idx = applied1.index(result)
                expected_snapshot = (
                    steps1[idx]["before"] if idx < len(steps1)
                    else (steps1[-1]["after"] if steps1 else (baseline or first.snapshot))
                )
                if is_object(result):
                    ok = _object_rollback(engine, runtime, fixes, plan, ctx["skeleton"], result, expected_snapshot)
                    record["rollback"].append({"fix_id": _fid(result), "verified": ok})
                    if not ok:
                        raise ContractError("Combined exact rollback failed")
                    continue
                if is_catalog(result):
                    if _fid(result) not in ctx["pending"]:
                        continue  # nothing of this fix ran (it failed while being derived)
                    ok = _catalog_rollback(engine, runtime, plan, scopes[result["fix_unit"]["spec_id"]],
                                           result, expected_snapshot, ctx["skeleton"], ctx["pending"])
                    record["rollback"].append({"fix_id": _fid(result), "verified": ok})
                    if not ok:
                        raise ContractError("Combined exact rollback failed")
                    continue
                runtime.sql(result["rendered_rollback_sql"])
                runtime.activate({n: r["setting"] for n, r in
                                  signature(expected_snapshot, plan["names"])["settings"].items()})
                restored = engine.collect(runtime)
                ok = bool(
                    signature(restored, plan["names"]) == signature(expected_snapshot, plan["names"])
                    and engine.assess(restored)["findings"] == engine.assess(expected_snapshot)["findings"]
                    # Unknown evidence never proves a rollback (as in workflow._setting_rollback);
                    # with retries a gapped rollback must stay a hard failure, not a retry.
                    and not blocking_gaps(restored)
                    and runtime.health()
                    and _objects_unchanged(ctx["skeleton"], restored, expected_snapshot)
                )
                record["rollback"].append({"fix_id": _fid(result), "verified": ok})
                if not ok:
                    raise ContractError("Combined exact rollback failed")
            if applied:
                terminal_capture.stage(record, runtime, "rollback", shots, "combined")
        except Exception as exc:
            record.update(status="FAILED", rollback_error=str(exc))
        finally:
            terminal_capture.finish(record)
            try:
                record["cleanup"] = runtime.close()
            except Exception:
                record["cleanup"] = {"verified": False}
            if not record["cleanup"].get("verified"):
                record["status"] = "CLEANUP_FAILED"
    # Rollback and cleanup stay strict: never retried, never partial.
    record["hard_failure"] = bool(
        record["status"] == "CLEANUP_FAILED" or "rollback_error" in record
        or (record["status"] != "VERIFIED" and not record.get("failed_fix_id")))
    emit(kind="combined_done", attempt=attempt, status=record["status"], phase="combined", step="done",
         text=(f"{title} passed: all {len(results)} fixes worked together and were undone exactly."
               if record["status"] == "VERIFIED" else f"{title} did not pass: {record.get('reason') or record.get('rollback_error') or 'cleanup failed'}."))
    return record


def _attempt_summary(record) -> dict:
    """An earlier combined attempt without its snapshots (the final one is combined_test)."""
    keep = ("run_id", "attempt", "status", "reason", "failed_fix_id", "failed_fix_ids", "failed_stage",
            "start_failed", "rollback_skipped", "phases", "restarts", "rollback", "rollback_error", "cleanup",
            "hard_failure")
    summary = {k: copy.deepcopy(record[k]) for k in keep if k in record}
    summary["steps"] = [{"fix_id": s["fix_id"], "phase": s.get("phase")} for s in record["steps"]]
    return summary


def run_batch(requests, service, requested_order=None, *, fix_all=False, progress=None, run_id=None):
    """Prepare every fix without a sandbox, then prove them together in one disposable
    sandbox; a fix is tested on its own only when it fails in the combined test.

    Synchronous; the API wraps it in a background job with a progress callback
    (``progress(event: dict)``). Returns (batch evidence, review bundle bytes or None).
    """
    batch = plan_batch(requests, service, requested_order, fix_all)
    return execute_batch(batch, service, progress=progress, run_id=run_id)


def _single_test(batch, service, request, fid, name, emit, text, individual, everything):
    """One fix's own sandbox test (service.run: reproduce the FAIL, fix, PASS, exact rollback,
    cleanup, adaptive retries), run only to find out why it failed in the combined test.
    Returns (passed, reason, result or None when the run raised before it had a result)."""
    emit(kind="individual_start", phase="individual", step="individual", fix_id=fid, text=text)
    try:
        result = service.run(request)
    except Exception as exc:
        reason = _exception_reason(exc)
        emit(kind="individual_done", status=FAILED, fix_id=fid, phase="individual", step="individual",
             text=f"{name} also FAILED on its own ({reason}).")
        return False, reason, None
    everything.append(result)
    data = None
    if result.get("status") == "VERIFIED":
        try:
            data = build_review_bundle(request, result, batch["engine"])
        except ContractError as exc:
            result = {**result, "review_bundle": {"status": "UNAVAILABLE", "reason": str(exc)}}
    history.record(request, result, data)
    individual.append({"run_id": result.get("run_id"), "fix_id": fid, "status": result.get("status")})
    passed = result.get("status") == "VERIFIED"
    reason = None if passed else _result_reason(result)
    emit(kind="individual_done", status=PASSED if passed else FAILED, fix_id=fid, phase="individual",
         step="individual", text=(f"{name} passed its own test." if passed
                                  else f"{name} also FAILED on its own ({reason})."))
    return passed, reason, result


def execute_batch(batch, service, *, progress=None, run_id=None):
    """Melvin's ruling of 12 Nov 2026: combined first, single tests only when needed.

    1. Every eligible fix is prepared WITHOUT a sandbox (service.prepare: the single run's
       validation, approved hash-pinned templates, fix unit, rendered SQL, risk review). A fix
       whose preparation fails is FAILED (stage "preparation"); the others continue.
    2. The combined test runs first. If it passes, the run is finished: no single tests.
    3. A fix that fails in the combined test (its per-step check names it) gets its own
       test: FAILED "individual" if that fails too, else FAILED "combined" (works alone,
       not with the others). It is left out and the rest are tested together again.
    4. PostgreSQL does not start after a joint restart: each restart fix of that round is
       tested on its own; only those failing alone are left out. If none fails alone, the
       whole round is left out (they cannot be told apart).
    A fix is packaged only if the FINAL combined test is VERIFIED including its exact undo;
    rollback and cleanup failures (also of a single test) stay hard failures.
    """
    emit = _Emit(progress)
    engine, first = batch["engine"], batch["first"]
    requests, eligible = batch["requests"], batch["eligible"]
    fixes = {}
    for r in requests:
        key = request_fix_id(r)
        if key in batch["not_eligible"]:
            fixes[key] = {"fix_id": _fix_id_for(batch, r), "status": NOT_ELIGIBLE, "stage": "planning",
                          "reason": batch["not_eligible"][key]}
    count = len(eligible)
    emit(kind="plan", count=count, phase="prepare", step="plan",
         text=f"Preparing {count} fix{'es' if count != 1 else ''} (no sandbox needed)"
              + (f"; {len(batch['not_eligible'])} not eligible (conflict)." if batch["not_eligible"] else "…"))
    results, individual, everything, request_of = [], [], [], {}
    for index, r in enumerate(eligible, 1):
        key = request_fix_id(r)
        profile = batch["profiles"].get(key)
        fallback = _fix_id_for(batch, r)
        emit(kind="prepare_start", phase="prepare", step="prepare", fix_id=fallback,
             text=f"Preparing fix {index} of {count}: {_label(profile, fallback)}…")
        try:
            item = service.prepare(r)
            if not _request_matches(r, item):
                raise ContractError("The prepared fix differs from the selected fix")
        except Exception as exc:
            reason = _exception_reason(exc)
            fixes[key] = {"fix_id": fallback, "status": FAILED, "stage": "preparation", "reason": reason}
            emit(kind="prepare_done", status=FAILED, fix_id=fallback, phase="prepare", step="prepare",
                 text=f"Fix {index} of {count} could not be prepared and was left out: {_name(profile, fallback)} ({reason}).")
            continue
        results.append(item)
        everything.append(item)
        request_of[_fid(item)] = r
        emit(kind="prepare_done", status=PASSED, fix_id=_fid(item), phase="prepare", step="prepare")
    reviews = {_fid(r): r["risk_review"] for r in results}
    ordered = recommend_order(list(reviews.values()), allow_missing_dependencies=True) if results else []
    requested_order = batch["requested_order"]
    if requested_order and results:
        known = set(reviews) | {f["fix_id"] for f in fixes.values()}
        if set(reviews) - set(requested_order) or set(requested_order) - known:
            raise ContractError("Selected order must contain every fix exactly once")
        chosen = [reviews[fid] for fid in requested_order if fid in reviews]
        seen = set()
        for review in chosen:
            if seen and fix_phase(review) < max(fix_phase(reviews[s]) for s in seen):
                raise ContractError("Selected order must put fixes that need no restart before fixes that need a restart")
            same_phase = {d for d in review.get("dependencies", []) if d in reviews
                          and fix_phase(reviews[d]) == fix_phase(review)}
            if not same_phase <= seen:
                raise ContractError("Selected order violates a prerequisite dependency")
            seen.add(review["fix_id"])
        ordered = chosen
    indexed = {_fid(r): r for r in results}
    remaining = [indexed[f["fix_id"]] for f in ordered]
    if requested_order and execution_order(remaining) != remaining:
        raise ContractError("Selected order must put a restart fix that builds on another restart fix's "
                            "setting after every other restart fix")
    attempts, record, retries, singles, tested, hard_single = [], None, 0, {}, {}, None
    while remaining:
        remaining = execution_order(remaining)
        record = _combined_attempt(batch, service, remaining, emit, len(attempts) + 1)
        attempts.append(record)
        failed = record.get("failed_fix_id")
        if record["status"] == "VERIFIED" or record["hard_failure"] or failed is None:
            break
        suspects = record.get("failed_fix_ids") or [failed]
        reason = record.get("reason")
        if record.get("start_failed"):
            emit(kind="culprit_search", phase="individual", step="individual",
                 text=f"PostgreSQL did not start after the restart for {', '.join(suspects)}; testing "
                      + ("each of these restart fixes on its own to find the cause…" if len(suspects) > 1
                         else "it on its own to find out why…"))
        outcomes = {}
        for number, fid in enumerate(suspects, 1):
            if fid in tested:
                # Already tested on its own after an earlier restart failure (and kept): reuse it.
                outcomes[fid] = tested[fid]
                continue
            name = _name(indexed[fid]["risk_review"], fid)
            text = (f"Testing restart fix {number} of {len(suspects)} on its own: {_label(indexed[fid]['risk_review'], fid)}…"
                    if record.get("start_failed") else
                    f"{name} FAILED in the combined test; testing it on its own to find out why…")
            passed, why, result = _single_test(batch, service, request_of[fid], fid, name, emit, text, individual,
                                               everything)
            outcomes[fid] = tested[fid] = (passed, why)
            if result is not None:
                singles[fid] = result
                if result.get("status") == "CLEANUP_FAILED":
                    # A sandbox that could not be removed stops everything (never partial).
                    hard_single = result
                    break
        if hard_single is not None:
            break
        if record.get("start_failed"):
            culprits = [fid for fid in suspects if not outcomes[fid][0]]
            dropped = culprits or suspects
        else:
            dropped = suspects
        remaining = [r for r in remaining if _fid(r) not in dropped]
        for fid in dropped:
            passed, why = outcomes[fid]
            key = request_fix_id(request_of[fid])
            if not passed:
                fixes[key] = {"fix_id": fid, "status": FAILED, "stage": "individual", "reason": why}
                text = f"{fid} FAILED on its own too and was left out ({why})."
            else:
                if record.get("start_failed") and len(dropped) > 1:
                    why = (f"{reason}. These restart fixes were restarted together ({', '.join(dropped)}); each "
                           "passes its own test, and which one stopped PostgreSQL starting cannot be told apart, so "
                           "all were left out")
                else:
                    why = ("It passes its own test, but not together with the other fixes; in the combined test: "
                           + str(reason))
                fixes[key] = {"fix_id": fid, "status": FAILED, "stage": "combined", "reason": why}
                text = (f"{fid} FAILED in the combined test and was left out: it passes on its own but not "
                        "together with the others.")
            emit(kind="combined_failed", status=FAILED, fix_id=fid, phase="combined", step="excluded",
                 text=text + (" Testing the others together again…"
                              if fid == dropped[-1] and remaining and retries < MAX_COMBINED_RETRIES else ""))
        if retries >= MAX_COMBINED_RETRIES:
            break
        retries += 1
    proven = remaining if record is not None and record["status"] == "VERIFIED" and hard_single is None else []
    hard = (hard_single is not None) or bool(record and record["hard_failure"])
    if hard_single is not None:
        stopped = ("Not tested further: the batch stopped because the sandbox of "
                   + ((hard_single.get("fix_unit") or {}).get("fix_id") or "another fix") + " could not be removed")
        culprit = (hard_single.get("fix_unit") or {}).get("fix_id")
        for r in eligible:
            key = request_fix_id(r)
            fid = next((f for f, req in request_of.items() if req is r), None)
            if fid is not None and fid == culprit:
                fixes[key] = {"fix_id": fid, "status": FAILED, "stage": "individual",
                              "reason": _result_reason(hard_single)}
            elif key not in fixes:
                fixes[key] = {"fix_id": fid or _fix_id_for(batch, r), "status": FAILED, "stage": "combined",
                              "reason": stopped}
    else:
        for result in remaining:
            key = request_fix_id(request_of[_fid(result)])
            if proven:
                fixes[key] = {"fix_id": _fid(result), "status": PASSED, "stage": "combined", "reason": None}
            else:
                reason = (("The combined test failed: " + (record.get("reason") or record.get("rollback_error")
                                                           or "its sandbox could not be removed")) if hard
                          else f"Not proven together: the combined test stopped after {MAX_COMBINED_RETRIES} retries")
                fixes[key] = {"fix_id": _fid(result), "status": FAILED, "stage": "combined", "reason": reason}
    if hard_single is not None:
        status = "CLEANUP_FAILED"
    elif hard:
        status = record["status"]
    elif proven:
        status = "VERIFIED" if all(f["status"] == PASSED for f in fixes.values()) and len(fixes) == len(requests) \
            else "PARTIAL"
    else:
        status = "FAILED"
    final = proven or remaining or execution_order([indexed[f["fix_id"]] for f in ordered])
    final_reviews = [r["risk_review"] for r in final]
    output = {
        "run_id": run_id or str(uuid.uuid4()),
        "status": status,
        # Only the single tests that actually ran (Melvin, 12 Nov): often none.
        "individual_runs": individual,
        "order_source": "DBA_SELECTED" if requested_order else "RECOMMENDED",
        "recommended_order": [_fid(r) for r in final],
        "fixes": [fixes[request_fix_id(r)] for r in requests if request_fix_id(r) in fixes],
        "phases": {"1": [_fid(r) for r in final if _phase(r) == 1], "2": [_fid(r) for r in final if _phase(r) == 2]},
        "risk_reviews": final_reviews,
        "requires_dba_review": True,
    }
    if record is not None:
        output["combined_test"] = record
        output["combined_attempts"] = [_attempt_summary(a) for a in attempts]
    if status in ("FAILED", "CLEANUP_FAILED") and not proven:
        output["reason"] = (_result_reason(hard_single) if hard_single is not None
                            else (record.get("reason") or record.get("rollback_error")) if record is not None
                            else "No selected fix could be prepared; the combined test was not started")
    output.update(
        schema_version="sandbox-batch-v1",
        snapshot_hash=digest(first.snapshot),
        spec_set_hash=engine.spec_set_hash,
        spec_hashes=engine.hashes,
        policy_profile=engine.policy_pin,
        fix_units=[r["fix_unit"] for r in final],
        demo_fixture_approval=any(is_fixture(r) for r in everything),
    )
    if proven and record["steps"]:
        output["sandbox_after_findings"] = {
            sid: f["status"] for sid, f in record["steps"][-1]["assessment"]["findings"].items()}
    if status not in ("VERIFIED", "PARTIAL"):
        emit(kind="done", status=status, phase="done", step="done", text=f"Finished: {status}.")
        return output, None
    emit(kind="bundle", phase="bundle", step="bundle", text="Building the package…")
    try:
        data = _batch_bundle(batch, output, proven, record, singles)
    except ContractError as exc:
        output["review_bundle"] = {"status": "UNAVAILABLE", "reason": str(exc)}
        data = None
    emit(kind="done", status=status, phase="done", step="done",
         text=f"Finished: {status}. {len(proven)} of {len(requests)} fixes passed together"
              + (" and are in the package." if data else "; no package could be built."))
    return output, data


def _compose(before, after, names):
    """``before`` with the setting rows (pg_settings and pg_file_settings) of ``names``
    taken from ``after``: both are observed collections of the same sandbox."""
    if not names:
        return before
    snap = copy.deepcopy(before)
    base, later = snap["baseline"], after["baseline"]
    base["settings"] = ([r for r in base.get("settings") or [] if r.get("name") not in names]
                        + copy.deepcopy([r for r in later.get("settings") or [] if r.get("name") in names]))
    if base.get("file_settings") is not None:
        base["file_settings"] = ([r for r in base["file_settings"] if r.get("name") not in names]
                                 + copy.deepcopy([r for r in later.get("file_settings") or [] if r.get("name") in names]))
    return snap


def _bundle_states(results, steps):
    """(before, after) for each fix's runner guard. The restart fixes of one round were
    written together and checked after one restart; on the target they are applied one at a
    time, so fix k's guard uses the round's observed state before the restart with the
    settings of the round's earlier fixes (and for ``after`` its own) taken from the
    observed state after the restart. No two fixes of a round write the same setting."""
    states, earlier, current = [], set(), None
    for result, step in zip(results, steps):
        if step.get("phase") != 2:
            states.append((step["before"], step["after"]))
            continue
        if step.get("restart_round") != current:
            earlier, current = set(), step.get("restart_round")
        unit = step.get("fix_unit") or result["fix_unit"]
        own = ({c["param"] for c in unit["changes"]} if "changes" in unit else {unit["apply"]["param"]})
        if own & earlier:
            raise ContractError("Two restart fixes of one round change " + ", ".join(sorted(own & earlier))
                                + "; no runner guard can be derived")
        states.append((_compose(step["before"], step["after"], earlier),
                       _compose(step["before"], step["after"], earlier | own)))
        earlier |= own
    return states


def _batch_bundle(batch, output, results, record, singles=None):
    """The DBA package for the fixes proven together. Each fix's folder is built from its
    preparation and the final VERIFIED combined test's records (Melvin, 12 Nov), never from
    a single-fix run; ``singles`` are the single tests that ran, reported where relevant."""
    engine, requests = batch["engine"], batch["requests"]
    singles = singles or {}
    ordered = output["risk_reviews"]
    scopes = {r["fix_unit"]["spec_id"]: batch["scopes"][r["fix_unit"]["spec_id"]] for r in results if is_catalog(r)}
    objects = [r for r in results if is_object(r)]
    files, configs, warnings = {}, [], []
    steps = record["steps"]
    if [s["fix_id"] for s in steps] != [_fid(r) for r in results]:
        raise ContractError("Review bundle: the combined steps differ from the fixes proven together")
    for position, (result, step, (before, after)) in enumerate(
            zip(results, steps, _bundle_states(results, steps)), 1):
        handoff = next(r for r in requests if _request_matches(r, result))
        # E2E Gate 1 decision 3: the package runner refuses apply-all without
        # --ack-client-impact when any fix can lock out clients.
        impact = client_impact.of_result(result)
        members = build_combined_fix_files(
            handoff, result, step, record, engine, prior_snapshot=before, applied_snapshot=after,
            package_run_id=output["run_id"], position=position, total=len(results),
            client_impact=bool(impact), single=singles.get(_fid(result)))
        if impact:
            warnings.append((_fid(result), (result.get("risk_review") or result.get("proposal") or {}).get("title"),
                             impact))
        # The sandbox restarts once per round of restart fixes (a fix building on another's
        # preload list waits for a second restart); the package must pause the same way.
        configs.append((_fid(result), json.loads(members["fix.json"]), step.get("restart_round")))
        prefix = _fid(result) + "/"
        files.update({prefix + k: v for k, v in members.items()})
    # Review N9: the combined stage PNGs are bundle members; keep names and hashes, not base64.
    bundled_output = copy.deepcopy(output)
    strip_screenshot_data(bundled_output["combined_test"].get("terminal_evidence"), "combined-")
    files["combined-evidence.json"] = json.dumps(bundled_output, indent=2).encode()
    # The per-fix files carry the scope line; repeat it on the combined front page.
    scope = ("DEMO FIXTURE APPROVAL — not human approval\n" if output.get("demo_fixture_approval")
             else "")
    left_out = [f for f in output["fixes"] if f["status"] != PASSED]
    if output["status"] == "PARTIAL":
        head = ("PARTIAL RESULT: only the fixes in this package passed together in one disposable sandbox "
                f"(combined test {record['run_id']}). Left out (not in this package):\n"
                + "".join(f"- {f['fix_id']}: {f['status']} ({f['stage']}): {f['reason']}\n" for f in left_out))
    else:
        head = f"All selected fixes passed together in one disposable sandbox (combined test {record['run_id']}).\n"
    restart_ids = output["phases"]["2"]
    restart_note = (("Restart fixes (" + ", ".join(restart_ids) + ") were written together and checked after one "
                     "restart of the sandbox. On the target, sh harden.sh apply-all pauses for a PostgreSQL restart "
                     "after each of them (each one's safety check expects the ones before it to be active) and tells "
                     "you exactly what to run next (see ONE COMMAND below). By hand "
                     "instead, apply them one at a time in the order below: each runner stops with RESTART_REQUIRED; "
                     "restart PostgreSQL, run verify, then continue.\n")
                    if restart_ids else "")
    files["README.txt"] = (
        scope + head + restart_note + "Use sh harden.sh apply-all (see ONE COMMAND below), or apply one complete fix at a time by hand in this order: "
        + ", ".join(output["recommended_order"])
        + "\n" + approval_text(engine.policy_pin)
        + "\nVerify each before proceeding. Roll back in REVERSE order.\nThe per-fix guard expects the preceding fixes to remain applied. If a DBA chooses another order, create and test a new batch.\nEach fix's report.html shows its own step in the combined test; combined-evidence.json records the whole combined test, and its individual_runs lists any fix that was also tested on its own.\nTarget changes have NOT been performed.\n"
        + "".join(f"\nSANDBOX LIMIT ({f['fix_id']}): {SANDBOX_LIMITS[f['setting']]}\n"
                  for f in ordered if f.get("setting") in SANDBOX_LIMITS)
        + (OBJECT_REHEARSAL_TEXT if objects else "")
        + "".join(PRELOAD_README.format(libs=", ".join(r["fix_unit"]["preload_added"]))
                  for r in results if is_catalog(r) and r["fix_unit"]["preload_added"])
        + (TLS_README if any(scope["tls"] for scope in scopes.values()) else "")
    ).encode()
    partial_html = ("<p class=\"notice\">PARTIAL RESULT: only the fixes listed below passed together in one "
                    "disposable sandbox. Left out:</p><ul>"
                    + "".join(f"<li>{escape(f['fix_id'])}: {escape(f['status'])} ({escape(f['stage'])}): "
                              f"{escape(str(f['reason']))}</li>" for f in left_out) + "</ul>"
                    if output["status"] == "PARTIAL" else "")
    files["report.html"] = (
        "<!doctype html><html><body><h1>Combined DBA review</h1>"
        + (f"<p>{escape(scope.strip())}</p>" if scope else "")
        + "<p>Sandbox verified. Target application NOT PERFORMED.</p>" + partial_html
        + (f"<p>{escape(restart_note.strip())}</p>" if restart_note else "") + "<p>"
        + escape(approval_text(engine.policy_pin))
        + "</p><ol>"
        + "".join(
            '<li><a href="'
            + f["fix_id"]
            + '/report.html">'
            + f["fix_id"]
            + "</a> — "
            + f["operational_risk"]
            + "</li>"
            for f in ordered
        )
        + "</ol><p>Apply one fix at a time; verify each. Rollback must follow reverse order. Review combined-evidence.json for combined test evidence.</p></body></html>"
    ).encode()
    # Task 2: the combined test's three stage screenshots, checked against their sha256 and,
    # when present, listed in a top-level manifest beside the combined evidence.
    shot_files, shot_html, shot_text = stage_screenshots(record.get("terminal_evidence"), "combined-")
    if shot_files:
        files["README.txt"] += shot_text.encode()
        files["report.html"] = files["report.html"].decode().replace("</body>", shot_html + "</body>", 1).encode()
        files.update(shot_files)
    if warnings:
        # E2E Gate 1 decision 3: direct, never a footnote: top of the README and report,
        # and a CLIENT-ACTIONS.txt the runner's --ack-client-impact refers to.
        actions = ("CLIENT ACTIONS REQUIRED BEFORE AND AFTER APPLYING THIS PACKAGE\n"
                   "These fixes harden the server but can block clients that are not updated. Hardening\n"
                   "this server does NOT update them. apply-all refuses to run without --ack-client-impact.\n\n"
                   + "".join(client_impact.text_block(fid, title, w) + "\n" for fid, title, w in warnings))
        files["CLIENT-ACTIONS.txt"] = actions.encode()
        files["README.txt"] = (f"!!! CLIENT ACTION REQUIRED for {len(warnings)} fix(es): read CLIENT-ACTIONS.txt "
                               "before applying. !!!\n\n").encode() + files["README.txt"]
        block = ('<section style="border:2px solid #b91c1c;background:#fef2f2;padding:16px;margin:16px 0">'
                 '<h2 style="color:#b91c1c;margin-top:0">\u26a0 Client action required</h2>'
                 "<p><strong>These fixes harden the server but will block clients that are not updated. "
                 "Hardening this server does not update them.</strong> Read CLIENT-ACTIONS.txt.</p>"
                 + "".join(f"<h3>{escape(fid)}: {escape(w['headline'])}</h3><p>{escape(w['what_breaks'])}</p>"
                           f"<p><strong>Right now:</strong> {escape(w['count_line'])}</p>"
                           f"<p><strong>Before applying:</strong> {escape(w['before_applying'])}</p>"
                           f"<p><strong>After applying:</strong> {escape(w['after_applying'])}</p>"
                           for fid, _, w in warnings) + "</section>")
        files["report.html"] = files["report.html"].decode().replace(
            "<h1>Combined DBA review</h1>", "<h1>Combined DBA review</h1>" + block, 1).encode()
    # E2E Gate 1, decision 2: one command for the whole package (sh harden.sh apply-all),
    # with the runner's own files, the apply order it reads and a top-level manifest that
    # is always written and covers every top-level file the runner allows.
    package_fixes = [{"fix_id": folder, "folder": folder, "requires": cfg.get("requires") or "none",
                      "client_impact": bool(cfg.get("client_impact")),
                      **({"restart_round": rnd} if (cfg.get("requires") == "restart" and rnd) else {})}
                     for folder, cfg, rnd in configs]
    # Every per-fix fix.json carries the target's identity (review_bundle); take it from there.
    first = configs[0][1]
    files.update(package_assets.package_files())
    files["package.json"] = package_assets.package_json(
        output["run_id"], first.get("database"), package_fixes,
        system_identifier=first.get("system_identifier"), target_id=first.get("target_id"),
        demo_fixture_approval=bool(output.get("demo_fixture_approval")))
    files["README.txt"] += package_assets.readme_text(package_fixes, bool(output.get("demo_fixture_approval"))).encode()
    files["manifest.json"] = json.dumps({
        "schema_version": "review-bundle-v1", "run_id": output["run_id"],
        "demo_fixture_approval": output["demo_fixture_approval"], "requires_dba_review": True,
        "snapshot_hash": output["snapshot_hash"], "spec_set_hash": engine.spec_set_hash,
        "files": package_assets.manifest_entries(files)}, indent=2).encode()
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return data.getvalue()
