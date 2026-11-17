"""Live E2E Gate 1 tests (DBGUARD_POC_LIVE=1, Docker): one-click fix-all and the one-command package.

    DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest -q tests/test_e2e_fix_all_live.py -x

Every database here is a disposable, run-labelled container created by this module and
removed afterwards: the demo registry (DemoResources), a published PG17 TARGET (the pinned
pgaudit image, standing in for the DBA's database) and the sandboxes the product creates.
Nothing touches a real database.

1. Fix-all through the background endpoints (POST /api/v1/sandbox/batches fix_all, poll GET):
   every fix the real fix plan offers for a snapshot collected from the target by the
   repository collector. The sandbox service uses the STOCK image, which has no pgaudit, so
   the 3.2 pgaudit fix genuinely stops PostgreSQL starting. Combined first (Melvin, 12 Nov):
   the combined test finds that at pgaudit's restart, pgaudit alone is then tested on its own
   (it fails there too), it is FAILED with that reason, left out of the package, the rest
   pass a second combined test, and the run is PARTIAL.
2. The combined package, run as the DBA would (sh harden.sh, DBGUARD_DSN with a password)
   against that same target: refusals, apply-all, restart, verify-all, reassessment,
   rollback-all with restarts until the original settings are back, pictures and the
   target-evidence zip checked by target_evidence.check() and the upload endpoint.
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import ExitStack
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.sandbox_poc.runtime import LABEL, STOCK_IMAGE, docker

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Disposable Docker integration (set DBGUARD_POC_LIVE=1)")

B = "cis-pg17-v1.1.0"
RISK = {"low": 0, "medium": 1, "high": 2}
# Broken on the target before collection (ALTER SYSTEM), on top of the PG17 defaults that
# already fail (log_connections, logging_collector, log_truncate_on_rotation, ...).
BROKEN = {"log_disconnections": "off", "ssl_min_protocol_version": "TLSv1.1",
          "debug_print_parse": "on", "log_hostname": "on"}
EXPECTED_FAILURE = "fix-pgaudit"  # 3.2: pgaudit is not installed in the STOCK sandbox image
REPO = Path(__file__).resolve().parents[1]
BATCH_TIMEOUT_SECONDS = 15 * 60


def _labelled(label, value):
    return docker("ps", "-aq", "--filter", f"label={label}={value}")


def _remove_labelled(label, value):
    for cid in _labelled(label, value).split():
        docker("rm", "-f", "-v", cid)


def _wait_for_batch(client, batch_id, seen):
    deadline = time.monotonic() + BATCH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        view = client.get(f"/api/v1/sandbox/batches/{batch_id}").json()
        seen.append(view)
        if view["status"] != "RUNNING":
            return view
        time.sleep(2)
    raise AssertionError("The fix-all batch did not finish within 15 minutes")


@pytest.fixture(scope="module")
def e2e(tmp_path_factory):
    """Registry + published target + fix-all batch through the API. Yields everything the
    tests need; removes every container it or the product created, even on failure."""
    from app.config import settings
    from app.collector_models import parse_snapshot
    from app.services.snapshot_service import SnapshotStore
    from app.services.spec_engine import RecordsIndex, load_spec
    from services.sandbox_poc import batch_jobs, history, router as routes
    from services.sandbox_poc.collector_intake import from_collector_bundle
    from services.sandbox_poc.collector_runner import collect_owned_target
    from services.sandbox_poc.demo import DEMO_LABEL, DemoResources
    from services.sandbox_poc.profiles import profile_store
    from services.sandbox_poc.service import SandboxService
    from services.sandbox_poc.shared import ROOT, SpecEngine
    from test_review_bundle_live import published_target

    base = tmp_path_factory.mktemp("e2e")
    mp = pytest.MonkeyPatch()
    mp.setenv("DBGUARD_HISTORY_DIR", str(base / "history"))
    mp.setattr(settings, "policy_profile_storage_dir", str(base / "profiles"))
    started = time.monotonic()
    timings = {}
    resources = DemoResources()
    run_ids = {"sandbox": []}
    with ExitStack() as stack:
        stack.callback(mp.undo)
        try:
            resources.start()
            # A profile approved by a named test reviewer in a tmp store (never the repo seed):
            # it supplies the CIS 3.2 pgaudit classes, so the 3.2 fix is offered.
            records = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")
            specs = [load_spec(p) for p in sorted((ROOT / f"catalog/specs/{B}").glob("*.yaml"))]
            store_p = profile_store(records, specs)
            draft = store_p.create_draft(profile_id="e2e-live-test-only", values={},
                                         pgaudit_log_classes=["ddl", "role", "write"])
            assert draft.approved is False
            profile = store_p.approve(draft.sha256, "Live Test Reviewer")
            engine = SpecEngine(specs, records, profile)

            target, dsn = stack.enter_context(published_target())
            run_ids["target"] = target.run_id
            for name, value in BROKEN.items():
                target.sql(f"ALTER SYSTEM SET {name}='{value}';")
            target.activate(BROKEN)
            bundle = collect_owned_target(target, engine)
            snapshot = from_collector_bundle(bundle, engine)
            original = engine.collect(target)
            store = SnapshotStore(base / "snapshots")
            receipt = store.save(parse_snapshot(bundle))
            service = SandboxService(resources.registry_url, image=STOCK_IMAGE)

            app = FastAPI()
            app.include_router(routes.router)
            app.dependency_overrides[routes.get_service] = lambda: service
            app.dependency_overrides[routes.get_snapshot_store] = lambda: store
            client = stack.enter_context(TestClient(app))

            plan = client.get(f"/api/v1/snapshots/{receipt.snapshot_id}/fix-plan",
                              params={"policy_profile": profile.sha256})
            assert plan.status_code == 200, plan.text
            plan = plan.json()
            offered = plan["recommended_order"]

            def body(fix, **change):
                item = {"snapshot_id": receipt.snapshot_id, "template_version": 1,
                        "evidence_ids": ["demo-evidence"], "environment": "test",
                        "control_id": fix["spec_id"], "retry_mode": "repeat",
                        "policy_profile": profile.sha256}
                if "shared_preload_libraries" in (fix.get("settings") or []):
                    item["list_template_version"] = plan["list_template_version"]
                item.update(change)
                return item

            fixes = [body(f) for f in offered]
            # Refused before anything runs: an unpinned template version and a fix the plan
            # does not offer (3.1.11 is NOT_APPLICABLE on this stderr-only target).
            refused = {}
            for label, request in {
                "unpinned_template": [*fixes[:-1], body(offered[-1], template_version=99)],
                "not_offered": [*fixes, body({"spec_id": f"{B}:3.1.11"})],
            }.items():
                response = client.post("/api/v1/sandbox/batches", json={"fixes": request, "fix_all": True})
                refused[label] = (response.status_code, response.json().get("detail"),
                                  batch_jobs.JOBS.busy(), len(history.list_runs()))

            t0 = time.monotonic()
            accepted = client.post("/api/v1/sandbox/batches", json={"fixes": fixes, "fix_all": True})
            post_seconds = time.monotonic() - t0
            assert accepted.status_code == 202, accepted.text
            accepted = accepted.json()
            run_ids["batch"] = accepted["batch_id"]
            views = []
            final = _wait_for_batch(client, accepted["batch_id"], views)
            timings["batch_seconds"] = round(time.monotonic() - t0, 1)
            result = final["result"]
            for item in result.get("individual_runs", []):
                try:
                    run_ids["sandbox"] += [a["run_id"] for a in history.get(item["run_id"])["result"].get("attempts", [])]
                except Exception:
                    run_ids["sandbox"].append(None)
            run_ids["sandbox"] += [a["run_id"] for a in result.get("combined_attempts", [])]
            package = client.get(f"/api/v1/sandbox/runs/{accepted['batch_id']}/bundle")
            timings["setup_seconds"] = round(time.monotonic() - started, 1)
            print(f"LIVE-RUN e2e-fix-all demo={resources.run_id} target={target.run_id} "
                  f"batch={accepted['batch_id']} status={result['status']} timings={timings}")
            yield {
                "engine": engine, "profile": profile, "target": target, "dsn": dsn, "snapshot": snapshot,
                "original": original, "offered": offered, "fixes": fixes, "refused": refused,
                "accepted": accepted, "post_seconds": post_seconds, "views": views, "final": final,
                "result": result, "package": package, "client": client, "run_ids": run_ids,
                "resources": resources, "timings": timings, "base": base,
            }
        finally:
            # The target is closed by published_target (ExitStack); the registry here.
            try:
                resources.close()
            finally:
                leftovers = []
                # Sandboxes only: the target is still open here (the ExitStack closes it after
                # this block) and is checked below, once it has been closed.
                for run_id in run_ids["sandbox"]:
                    if run_id and _labelled(LABEL, run_id):
                        leftovers.append(run_id)
                        _remove_labelled(LABEL, run_id)
                if _labelled(DEMO_LABEL, resources.run_id):
                    leftovers.append(resources.run_id)
                    _remove_labelled(DEMO_LABEL, resources.run_id)
    # Every container this module created is gone (checked by its own run labels).
    assert not _labelled(DEMO_LABEL, resources.run_id)
    assert run_ids.get("target") and not _labelled(LABEL, run_ids["target"])
    assert not leftovers, leftovers


# ---------------------------------------------------------------------------
# 1. Fix-all sandbox run through the background endpoints
# ---------------------------------------------------------------------------

def test_fix_all_through_the_background_endpoints_is_partial_ordered_and_cleaned_up(e2e):
    offered, result, final = e2e["offered"], e2e["result"], e2e["final"]
    ids = [f["fix_id"] for f in offered]
    restart_ids = [f["fix_id"] for f in offered if f["requires"] == "restart"]
    # The real fix plan offers at least 10 setting fixes, including at least 2 restart fixes
    # besides the one that must fail, and the failing one itself.
    assert len(ids) >= 10 and len(set(ids)) == len(ids), ids
    assert EXPECTED_FAILURE in ids and "fix-logging_collector" in restart_ids
    assert len([i for i in restart_ids if i != EXPECTED_FAILURE]) >= 2, restart_ids
    assert {f["spec_id"] for f in offered} >= {f"{B}:3.1.3", f"{B}:3.2", f"{B}:5.6", f"{B}:6.9", f"{B}:6.10"}

    # Refusals before any container or job: 422, no batch running, nothing recorded.
    for label, (status, detail, busy, runs) in e2e["refused"].items():
        assert status == 422, (label, detail)
        assert busy is False and runs == 0, (label, busy, runs)
    assert "template version is unavailable" in e2e["refused"]["unpinned_template"][1]

    # The POST returns at once with the job; GET shows progress, then the result.
    accepted = e2e["accepted"]
    assert e2e["post_seconds"] < 10
    assert accepted["status"] == "RUNNING" and accepted["total_fixes"] == len(ids)
    assert accepted["not_eligible"] == []
    assert any(v["status"] == "RUNNING" and v["result"] is None for v in e2e["views"])
    assert final["status"] == "PARTIAL" and result["status"] == "PARTIAL", result.get("reason")
    assert final["done"] == final["total"]

    # The failing fix: FAILED in the combined test, then in its own sandbox test (the only
    # single test of the run), with the real start-failure reason.
    by_id = {f["fix_id"]: f for f in result["fixes"]}
    assert set(by_id) == set(ids)
    failed = by_id[EXPECTED_FAILURE]
    assert (failed["status"], failed["stage"]) == ("FAILED", "individual"), failed
    assert "shared_preload_libraries names 'pgaudit', which is not installed" in failed["reason"], failed
    assert all(f["status"] == "PASSED" for fid, f in by_id.items() if fid != EXPECTED_FAILURE), by_id
    passed = [i for i in ids if i != EXPECTED_FAILURE]

    # Ordering: phase 1 (no restart) then phase 2 (restart); low -> high risk inside each.
    order = result["recommended_order"]
    assert sorted(order) == sorted(passed) and EXPECTED_FAILURE not in order
    reviews = {r["fix_id"]: r for r in result["risk_reviews"]}
    assert [r["fix_id"] for r in result["risk_reviews"]] == order
    phase1, phase2 = result["phases"]["1"], result["phases"]["2"]
    assert order == phase1 + phase2
    assert phase2 and all(reviews[f]["requires"] == "restart" for f in phase2)
    assert phase1 and all(reviews[f]["requires"] != "restart" for f in phase1)
    for phase in (phase1, phase2):
        ranks = [RISK[reviews[f]["operational_risk"]] for f in phase]
        assert ranks == sorted(ranks), [(f, reviews[f]["operational_risk"]) for f in phase]
    combined = result["combined_test"]
    assert combined["status"] == "VERIFIED"
    assert [s["fix_id"] for s in combined["steps"]] == order
    assert [s["phase"] for s in combined["steps"]] == [1] * len(phase1) + [2] * len(phase2)
    # Exactly one sandbox restart: the remaining restart fixes share no setting
    # (pgaudit, the only fix that would chain on shared_preload_libraries, was left out).
    assert combined["restarts"] == 1
    assert {s.get("restart_round") for s in combined["steps"] if s["phase"] == 2} == {1}
    assert all(s.get("joint_restart") for s in combined["steps"] if s["phase"] == 2)
    # 3.1.7 depends on logging_collector: written in phase 1, verified after the restart.
    truncate = next(s for s in combined["steps"] if s["fix_id"] == "fix-log_truncate_on_rotation")
    assert truncate["verification"] == "AFTER_RESTART"
    assert truncate["verified_after_restart"]["status"] == "PASS"
    assert [x["fix_id"] for x in combined["rollback"]] == list(reversed(order))
    assert all(x["verified"] for x in combined["rollback"]) and combined["cleanup"]["verified"]
    first_attempt = result["combined_attempts"][0]
    assert [a["status"] for a in result["combined_attempts"]] == ["FAILED", "VERIFIED"]
    assert first_attempt["start_failed"] is True and first_attempt["failed_fix_ids"] == [EXPECTED_FAILURE]
    assert first_attempt["cleanup"]["verified"] and first_attempt["hard_failure"] is False
    assert [(i["fix_id"], i["status"]) for i in result["individual_runs"]] == [(EXPECTED_FAILURE, "FAILED")]

    # Progress: plain-English step text, in order, from start to the package.
    texts = [s["text"] for s in final["steps"]]
    assert texts and all(isinstance(t, str) and t.strip() for t in texts)
    assert texts[0] == f"Preparing {len(ids)} fixes (no sandbox needed)…"
    for index, fid in enumerate(ids, 1):
        assert any(t.startswith(f"Preparing fix {index} of {len(ids)}: ") for t in texts), index
    assert not any(t.startswith("Testing fix ") for t in texts)
    assert (f"PostgreSQL did not start after the restart for {EXPECTED_FAILURE}; testing it on its own to find "
            "out why…") in texts
    assert any(t.startswith(f"{EXPECTED_FAILURE} FAILED on its own too and was left out (") and "pgaudit" in t
               for t in texts), texts
    assert any(t.startswith(f"Combined test: starting one disposable sandbox for {len(ids)} fixes "
                            f"({len(phase1)} without restart, {len(phase2) + 1} with restart)") for t in texts)
    assert any(t.startswith(f"Combined test (retry 1 of 3): starting one disposable sandbox for {len(passed)} "
                            f"fixes ({len(phase1)} without restart, {len(phase2)} with restart)") for t in texts)
    restarts = [t for t in texts if "restarting the sandbox database" in t]
    assert restarts == [f"Combined test, phase 2: restarting the sandbox database once for {len(phase2)} "
                        "restart fixes…",
                        f"Combined test, phase 2: restarting the sandbox database again for {EXPECTED_FAILURE}, "
                        "which builds on a setting an earlier restart fix changed…",
                        f"Combined test (retry 1 of 3), phase 2: restarting the sandbox database once for "
                        f"{len(phase2)} restart fixes…"], restarts
    assert any("checking log_truncate_on_rotation again now that logging_collector is on" in t for t in texts)
    assert "Building the package…" in texts
    assert texts[-1] == (f"Finished: PARTIAL. {len(passed)} of {len(ids)} fixes passed together and are in "
                         "the package.")
    secret = e2e["dsn"]
    assert not any(secret in t or "password" in t.lower() for t in texts)

    # The package holds exactly the passing fixes, in order; the failed one only as "left out".
    package = e2e["package"]
    assert package.status_code == 200
    with zipfile.ZipFile(io.BytesIO(package.content)) as z:
        assert z.testzip() is None
        names = z.namelist()
        package_json = json.loads(z.read("package.json"))
        readme = z.read("README.txt").decode()
        actions = z.read("CLIENT-ACTIONS.txt").decode()
    assert [f["fix_id"] for f in package_json["fixes"]] == order
    assert not any(n.startswith(EXPECTED_FAILURE + "/") for n in names)
    assert all(f"{fid}/fix.json" in names and f"{fid}/runner.py" in names for fid in order)
    assert {"harden.sh", "package_runner.py", "terminal_evidence.py", "visual_evidence.py",
            "package.json", "manifest.json", "CLIENT-ACTIONS.txt"} <= set(names)
    assert f"- {EXPECTED_FAILURE}: FAILED (individual)" in readme and "PARTIAL RESULT" in readme
    impact = sorted(f["fix_id"] for f in package_json["fixes"] if f["client_impact"])
    assert impact == sorted(["fix-ssl_min_protocol_version", "fix-ssl_ciphers", "fix-passwordcheck"]), impact
    assert all(f"[{fid}]" in actions for fid in impact)
    assert package_json["demo_fixture_approval"] is True
    assert [f["requires"] for f in package_json["fixes"]] == [reviews[f]["requires"] for f in order]

    # Every sandbox (the two combined tests and pgaudit's own test) was removed: run labels.
    sandboxes = e2e["run_ids"]["sandbox"]
    assert 3 <= len(sandboxes) <= 5 and all(sandboxes), sandboxes
    assert len(set(sandboxes)) == len(sandboxes)
    assert [r for r in sandboxes if _labelled(LABEL, r)] == []
    print(f"LIVE-RUN fix-all batch={accepted['batch_id']} fixes={len(ids)} passed={len(passed)} "
          f"sandboxes={len(sandboxes)} timings={e2e['timings']}")


# ---------------------------------------------------------------------------
# 2. The package end to end against the disposable target
# ---------------------------------------------------------------------------

def _settings_view(engine, target):
    """Value, source and file entries of every setting spec plus the catalog-fix settings."""
    from services.sandbox_poc.catalog_fixes import catalog_signature
    snap = engine.collect(target)
    names = [s["check"]["setting_name"] for s in engine.specs
             if "check" in s and s["check"].get("kind") != "catalog"]
    extra = {n: target.sql(f"SHOW {n};") for n in ("shared_preload_libraries", "ssl_ciphers", "logging_collector")}
    return catalog_signature(snap, names + ["shared_preload_libraries", "ssl_ciphers"]), extra


def _status_lines(stdout):
    return {m.group(1): m.group(2) for m in re.finditer(r"^\d+\. (fix-[^:]+): (.*)$", stdout, re.M)}


def test_package_apply_verify_rollback_on_the_disposable_target(e2e, tmp_path):
    from services.sandbox_poc import history, router as routes, target_evidence
    from services.sandbox_poc.bundle_assets import package_runner, terminal_evidence as te
    from services.sandbox_poc.collector_intake import from_collector_bundle
    from services.sandbox_poc.collector_runner import collect_owned_target
    from services.sandbox_poc.shared import ContractError

    assert e2e["package"].status_code == 200
    engine, target, dsn = e2e["engine"], e2e["target"], e2e["dsn"]
    run_id = e2e["result"]["run_id"]
    order = e2e["result"]["recommended_order"]
    params = te.parse_dsn(dsn)
    password, user, port = params["password"], params["user"], params["port"]
    assert password and len(password) >= 16 and port and user
    secrets = [password, "127.0.0.1", f"127.0.0.1:{port}", f"port={port}", f"user={user}", user, dsn]

    folder = tmp_path / "package"
    folder.mkdir()
    with zipfile.ZipFile(io.BytesIO(e2e["package"].content)) as z:
        z.extractall(folder)
    evidence = tmp_path / "evidence"
    # The private folder for terminal pictures is made in the system temp folder; give the
    # runner a fresh, anonymous one so "deleted afterwards" can be checked exactly.
    temp_root = Path(tempfile.mkdtemp(prefix="dbguard-e2e-tmp-"))
    venv_bin = str(Path(sys.executable).parent)
    env = {**os.environ, "DBGUARD_DSN": dsn, "TMPDIR": str(temp_root),
           "PATH": venv_bin + os.pathsep + os.environ.get("PATH", "")}
    outputs = []

    def sh(*args, evidence_dir=evidence, screenshots="terminal"):
        argv = ["sh", str(folder / "harden.sh"), *args, "--allow-demo", "--screenshots", screenshots,
                "--evidence-dir", str(evidence_dir)]
        done = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=600, cwd=str(tmp_path))
        outputs.append((args, done.stdout, done.stderr))
        print(f"$ harden.sh {' '.join(args)} -> {done.returncode}\n{done.stdout}{done.stderr}")
        return done

    def restart():
        target.restart()  # pg_ctl inside the run-owned container; `docker restart` would wipe its tmpfs
        deadline = time.monotonic() + 60
        while target.sql("SELECT 1;") != "1":
            assert time.monotonic() < deadline
            time.sleep(0.5)

    original, original_extra = _settings_view(engine, target)
    try:
        # --- status: nothing applied on the untouched target -----------------------------
        status = sh("status")
        assert status.returncode == 0, status.stderr
        lines = _status_lines(status.stdout)
        assert list(lines) == order
        # Fix of 16 Nov: the first fix is checked against its tested "before" state; every later
        # fix's "before" assumes the fixes ahead of it are applied, so it reads "not applied yet".
        not_yet = "not applied yet (checked when the fixes before it are applied)"
        assert lines[order[0]] == "not applied", lines
        assert all(lines[f] == not_yet for f in order[1:]), lines

        # --- refusals: nothing applied -----------------------------------------------------
        no_impact_ack = sh("apply-all", "--ack-prerequisites")
        assert no_impact_ack.returncode == package_runner.EXIT_REFUSED, no_impact_ack.stdout
        assert "--ack-client-impact" in no_impact_ack.stderr and "CLIENT-ACTIONS.txt" in no_impact_ack.stderr
        for fid in ("fix-ssl_min_protocol_version", "fix-ssl_ciphers", "fix-passwordcheck"):
            assert fid in no_impact_ack.stderr
        no_prereq_ack = sh("apply-all", "--ack-client-impact")
        assert no_prereq_ack.returncode == package_runner.EXIT_REFUSED
        assert not (folder / package_runner.STATE_FILE).exists()
        assert _settings_view(engine, target) == (original, original_extra)
        assert not list(evidence.glob("*.png"))

        # --- apply-all: the no-restart fixes, then one restart fix; it pauses for a restart
        # after every restart fix (fix of 16 Nov: each restart fix's guard expects the ones
        # before it active) and prints the exact command to run next. Follow it like a DBA.
        restart_fixes = e2e["result"]["phases"]["2"]
        applied = sh("apply-all", "--ack-prerequisites", "--ack-client-impact")
        assert applied.returncode == package_runner.EXIT_RESTART, applied.stdout + applied.stderr
        state = json.loads((folder / package_runner.STATE_FILE).read_text())
        assert [e["fix_id"] for e in state["applied"]] == order[:len(order) - len(restart_fixes) + 1]
        assert [e["fix_id"] for e in state["applied"] if e["status"] == "restart_pending"] == restart_fixes[:1]
        assert target.sql("SHOW logging_collector;") == "off"  # written, not active: no restart by the package
        assert (evidence / "event-before.json").is_file()
        restarts = 0
        while applied.stdout.strip().splitlines()[-1] != package_runner.RESTART_LINE:
            assert applied.returncode == package_runner.EXIT_RESTART, applied.stdout + applied.stderr
            printed = re.search(r"then run: sh harden\.sh (.+)$", applied.stdout.strip().splitlines()[-1])
            assert printed and printed.group(1).startswith("apply-all"), applied.stdout
            restart()
            restarts += 1
            applied = sh(*[a for a in printed.group(1).split() if a != "--allow-demo"])
        assert restarts == len(restart_fixes) - 1
        state = json.loads((folder / package_runner.STATE_FILE).read_text())
        assert [e["fix_id"] for e in state["applied"]] == order

        # --- the DBA restarts PostgreSQL, then verify-all ----------------------------------
        restart()
        verified = sh("verify-all")
        assert verified.returncode == package_runner.EXIT_OK, verified.stdout + verified.stderr
        assert f"All {len(order)} fix(es) verified." in verified.stdout
        assert target.sql("SHOW logging_collector;") == "on"
        assert target.sql("SHOW shared_preload_libraries;") == "passwordcheck"
        assert target.sql("SHOW ssl_min_protocol_version;") == "TLSv1.2"
        status = sh("status")
        assert status.returncode == 0
        lines = _status_lines(status.stdout)
        assert list(lines) == order and all(v.startswith("applied") for v in lines.values()), status.stdout

        # --- reassessment of a fresh collection against the recorded run --------------------
        fresh = from_collector_bundle(collect_owned_target(target, engine), engine)
        verdict = history.compare(run_id, fresh, engine)
        assert verdict["status"] == "TARGET_REASSESSMENT_CONFIRMED", (verdict["regressions"], verdict["gaps"])
        assert verdict["assessment"]["findings"][f"{B}:3.1.3"]["status"] == "PASS"

        # --- rollback-all, with a restart each time it asks for one -------------------------
        rounds = 0
        while True:
            rolled = sh("rollback-all")
            rounds += 1
            assert rounds <= len(order) + 1
            if rolled.returncode == package_runner.EXIT_OK:
                break
            assert rolled.returncode == package_runner.EXIT_RESTART, rolled.stdout + rolled.stderr
            assert package_runner.RESTART_ROLLBACK_LINE in rolled.stdout
            restart()
            confirmed = sh("verify-all", "--rollback")
            assert confirmed.returncode == package_runner.EXIT_OK, confirmed.stdout + confirmed.stderr
        assert rounds == len(restart_fixes) + 1
        assert "Every fix this package applied has been rolled back and verified." in rolled.stdout
        state = json.loads((folder / package_runner.STATE_FILE).read_text())
        assert state["applied"] == [] and [e["fix_id"] for e in state["rolled_back"]] == list(reversed(order))
        # The target is exactly as before: values, sources and file entries.
        assert _settings_view(engine, target) == (original, original_extra)
        status = sh("status")
        after_rollback = _status_lines(status.stdout)
        assert status.returncode == 0 and after_rollback[order[0]] == "not applied", status.stdout
        assert all(after_rollback[f] == not_yet for f in order[1:]), status.stdout

        # --- pictures: three stages; terminal if the tools exist here, else rendered + reason --
        terminal_ready = bool(te.psql_path() and all(shutil.which(t) for t in ("vhs", "ttyd", "ffmpeg"))
                              and te.terminal_browser())
        modes = {}
        for stage in ("before", "after", "rollback"):
            event = json.loads((evidence / f"event-{stage}.json").read_text())
            png = evidence / f"{stage}.png"
            assert event["run_id"] == run_id and event["stage"] == stage
            assert event["status"] == "CAPTURED", event
            assert png.is_file() and png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
            assert event["png_sha256"] == hashlib.sha256(png.read_bytes()).hexdigest()
            assert event["database"] == "dbguard_sandbox"
            assert event["system_identifier"] == e2e["snapshot"]["baseline"]["identity"]["system_identifier"]
            modes[stage] = (event["mode"], event["reason"], event["typed_command"])
            if terminal_ready:
                assert event["mode"] == "terminal", event["reason"]
                typed = event["typed_command"]
                assert re.fullmatch(r"\S+/psql service=dbguard -X -e -v ON_ERROR_STOP=1 -f \S+/dbguard-"
                                    + stage + r"\.sql", typed), typed
                assert typed.split(" -f ")[1].startswith(str(temp_root))
                assert not Path(typed.split(" -f ")[1]).parent.exists()
            else:
                assert event["mode"] == "rendered", event
                assert "Terminal capture UNAVAILABLE" in event["reason"]
                if te.psql_path() is None:
                    assert "psql is not installed at a standard path" in event["reason"]
                assert event["typed_command"] is None
            queries = json.loads((evidence / f"queries-{stage}.json").read_text())
            assert queries["run_id"] == run_id and queries["queries"]
            shown = {q["title"] for q in queries["queries"]}
            assert "Effective value of logging_collector" in shown
        after = json.loads((evidence / "queries-after.json").read_text())["queries"]
        assert next(q for q in after if q["title"] == "Effective value of logging_collector")["rows"] == [["on"]]
        rollback = json.loads((evidence / "queries-rollback.json").read_text())["queries"]
        assert next(q for q in rollback if q["title"] == "Effective value of logging_collector")["rows"] == [["off"]]

        # --- no connection detail anywhere the package wrote or printed --------------------
        written = [p for p in evidence.rglob("*") if p.is_file()]
        written += [folder / package_runner.STATE_FILE]
        for path in written:
            if path.suffix == ".zip":
                with zipfile.ZipFile(path) as z:
                    blobs = [(f"{path.name}:{n}", z.read(n)) for n in z.namelist()]
            else:
                blobs = [(path.name, path.read_bytes())]
            for name, data in blobs:
                for value in secrets:
                    assert value.encode() not in data, (name, "leaks a connection value")
        for args, out, err in outputs:
            for value in secrets:
                assert value not in out and value not in err, (args, "prints a connection value")
            assert not re.search(rf"\b{port}\b", out + err), args
        # The private temp folder (connection files, tape, SQL) is gone.
        assert not [p.name for p in temp_root.iterdir()], list(temp_root.iterdir())

        # --- target-evidence zip: checked against the recorded run, tampering refused ------
        archive = evidence / f"target-evidence-{run_id}.zip"
        data = archive.read_bytes()
        record = history.get(run_id)
        receipt = target_evidence.check(data, run_id, record)
        assert receipt["status"] == target_evidence.STATUS  # security review finding 1: consistent, not authenticated
        assert set(receipt["stages"]) == {"before", "after", "rollback"}
        assert all(s["png_sha256"] and s["mode"] in ("terminal", "rendered") for s in receipt["stages"].values())
        assert receipt["stages"]["after"]["step"]["command"] == "verify-all"
        assert receipt["stages"]["rollback"]["step"]["command"] in ("rollback-all", "verify-all --rollback")
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            members = {n: z.read(n) for n in z.namelist()}

        def rezip(changed):
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w") as z:
                for n, d in {**members, **changed}.items():
                    z.writestr(n, d)
            return out.getvalue()

        png = members["before.png"]
        tampered = rezip({"before.png": png[:-20] + bytes(b ^ 0xFF for b in png[-20:])})
        with pytest.raises(ContractError, match="before.png does not match its fingerprint"):
            target_evidence.check(tampered, run_id, record)
        with pytest.raises(ContractError, match="different run"):
            target_evidence.check(data, "0" * 32, record)
        with pytest.raises(ContractError, match="Unexpected file"):
            target_evidence.check(rezip({"notes.txt": b"x"}), run_id, record)
        # And through the step 7 upload endpoint.
        app = FastAPI()
        app.include_router(routes.router)
        with TestClient(app) as client:
            bad = client.post(f"/api/v1/history/{run_id}/target-evidence",
                              files={"file": ("target-evidence.zip", tampered, "application/zip")})
            assert bad.status_code == 422, bad.text
            ok = client.post(f"/api/v1/history/{run_id}/target-evidence",
                             files={"file": (archive.name, data, "application/zip")})
            assert ok.status_code == 200, ok.text
            assert ok.json()["status"] == target_evidence.STATUS  # security review finding 1: consistent, not authenticated
            assert "png_base64" not in json.dumps(ok.json())
        print(f"LIVE-RUN package run={run_id} fixes={len(order)} restarts_on_rollback={rounds - 1} "
              f"pictures={ {s: m[0] for s, m in modes.items()} } reason={modes['before'][1]!r}")
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


# ---------------------------------------------------------------------------
# 3. Chained restart fixes (5.6 passwordcheck then 3.2 pgaudit): two restart rounds
# ---------------------------------------------------------------------------

def test_package_with_chained_preload_fixes_follows_its_own_restart_instructions(e2e, tmp_path):
    """The sandbox proves 5.6 + 3.2 with two restarts (pgaudit builds on the list passwordcheck
    wrote). On the target the package must never report a failure for that proven order when
    the DBA does exactly what it prints: restart when asked, then run the printed command."""
    from services.sandbox_poc import history
    from services.sandbox_poc.batch import run_batch
    from services.sandbox_poc.bundle_assets import package_runner
    from services.sandbox_poc.collector_intake import from_collector_bundle
    from services.sandbox_poc.collector_runner import collect_owned_target
    from services.sandbox_poc.handoff import SandboxHandoff, build_handoff
    from services.sandbox_poc.service import SandboxService
    from services.sandbox_poc.templates import export_reference
    from test_review_bundle_live import published_target

    engine, resources = e2e["engine"], e2e["resources"]
    sandboxes = []
    with published_target() as (target, dsn):
        try:
            snapshot = from_collector_bundle(collect_owned_target(target, engine), engine)
            original = _settings_view(engine, target)
            list_ref = export_reference(resources.registry_url, 1, ["demo-evidence"], "test",
                                        registry_name="set_config_list")[0]
            requests = []
            for rec in ("5.6", "3.2"):
                handoff = build_handoff(engine, snapshot, resources.handoff.template_ref)
                handoff.control_id, handoff.retry_mode = f"{B}:{rec}", "repeat"
                handoff.list_template_ref = list_ref
                requests.append(SandboxHandoff.model_validate(handoff.model_dump()))
            output, data = run_batch(requests, SandboxService(resources.registry_url), fix_all=True)
            for item in output["individual_runs"]:
                sandboxes += [a["run_id"] for a in history.get(item["run_id"])["result"]["attempts"]]
            sandboxes += [a["run_id"] for a in output.get("combined_attempts", [])]
            assert output["status"] == "VERIFIED", output.get("reason")
            assert output["recommended_order"] == ["fix-passwordcheck", "fix-pgaudit"]
            assert output["combined_test"]["restarts"] == 2
            assert [s["restart_round"] for s in output["combined_test"]["steps"]] == [1, 2]
            history.record(requests[0], output, data)

            folder = tmp_path / "package"
            folder.mkdir()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(folder)
            env = {**os.environ, "DBGUARD_DSN": dsn,
                   "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")}
            log = []

            def sh(*args):
                done = subprocess.run(["sh", str(folder / "harden.sh"), *args, "--allow-demo", "--screenshots",
                                       "off", "--evidence-dir", str(tmp_path / "evidence")],
                                      env=env, capture_output=True, text=True, timeout=600)
                log.append((args, done.returncode, done.stdout, done.stderr))
                print(f"$ harden.sh {' '.join(args)} -> {done.returncode}\n{done.stdout}{done.stderr}")
                return done

            done = sh("apply-all", "--ack-prerequisites", "--ack-client-impact")
            for _ in range(4):
                assert done.returncode != package_runner.EXIT_FAILED, log
                if done.returncode == package_runner.EXIT_OK:
                    break
                assert done.returncode == package_runner.EXIT_RESTART, log
                target.restart()
                printed = re.search(r"then run: sh harden\.sh (.+)$", done.stdout.strip().splitlines()[-1])
                assert printed, done.stdout
                done = sh(*printed.group(1).split())
            state = json.loads((folder / package_runner.STATE_FILE).read_text())
            assert [(e["fix_id"], e["status"]) for e in state["applied"]] == [
                ("fix-passwordcheck", "verified"), ("fix-pgaudit", "verified")], log
            assert target.sql("SHOW shared_preload_libraries;") == "passwordcheck, pgaudit"
            assert target.sql("SHOW pgaudit.log;") == "ddl,role,write"
            # Undo, restarting whenever asked, back to the exact original settings.
            done = sh("rollback-all")
            for _ in range(4):
                if done.returncode == package_runner.EXIT_OK and "Every fix this package applied" in done.stdout:
                    break
                if done.returncode == package_runner.EXIT_RESTART:
                    target.restart()
                    done = sh("verify-all", "--rollback")
                    assert done.returncode == package_runner.EXIT_OK, log
                    if "Next: sh harden.sh rollback-all" in done.stdout:
                        done = sh("rollback-all")
                    continue
                raise AssertionError(log)
            assert _settings_view(engine, target) == original
        finally:
            print(f"LIVE-RUN chained target={target.run_id} sandboxes={','.join(map(str, sandboxes))}")
    assert sandboxes and [r for r in sandboxes if _labelled(LABEL, r)] == []
