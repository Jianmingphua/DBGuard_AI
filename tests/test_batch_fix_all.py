"""Fix-all batches (Melvin's rulings of 10 and 12 Nov), with fake sandboxes only.

1. No six-fix limit: any number of offered fixes, each once; unknown and duplicate refused.
2. Two phases: no-restart fixes first (lowest risk first), then restart fixes with ONE
   restart; a fix that depends on logging_collector is verified after that restart.
3. Combined first (12 Nov): every fix is prepared without a sandbox, then tested together;
   a fix gets its own test only when it fails there. A failing fix is FAILED and left out,
   the rest continue (PARTIAL); a combined failure at step k is retried without k, at most
   three times. Rollback and cleanup stay hard.
4. Background job: POST returns at once, GET shows progress then the result; 409 while one
   runs; a batch whose process died is INTERRUPTED.
5. No sandbox screenshots in a background batch.
"""
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import threading
import time
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.sandbox_poc import batch as batch_module
from services.sandbox_poc import batch_jobs, history, planning, profiles
from services.sandbox_poc import router as routes
from services.sandbox_poc import terminal_capture as tc
from services.sandbox_poc.provenance import setting_rows
from services.sandbox_poc.shared import ContractError, SpecEngine
from services.sandbox_poc.upstream import PrepareRequest
from tests.test_object_sandbox import (ObjectRuntime, effect_for, engine, object_template, planted,  # noqa: F401
                                       props, proposals_for, snapshot)

B = "cis-pg17-v1.1.0"
SOURCE = {"baseline": {"gaps": []}, "active": []}


# ---------------------------------------------------------------------------
# A small fake world: fixes are named settings; a sandbox holds the set of applied fixes.
# ---------------------------------------------------------------------------

class Request(SimpleNamespace):
    def model_dump_json(self):
        return json.dumps({"control_id": self.control_id, "policy_profile_sha256": None, "snapshot": SOURCE})


class Runtime:
    def __init__(self, world, number):
        self.world, self.number = world, number
        self.run_id, self.name = f"combined-{number}", f"fake-combined-{number}"
        self.written, self.active = set(), set()
        self.restarts, self.log, self.closed = 0, [], False

    def start(self):
        pass

    def sql(self, script):
        if getattr(self, "down", False):
            raise RuntimeError('psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed')
        self.log.append(script)
        verb, _, fid = script.partition(" ")
        if verb == "APPLY":
            if (self.number, fid) in self.world.apply_errors:
                raise RuntimeError("psql:<stdin>:1: ERROR: apply failed")
            self.written.add(fid)
        elif verb == "ROLLBACK" and (self.number, fid) not in self.world.rollback_stuck:
            self.written.discard(fid)
        return "t"

    def activate(self, expected):
        # Like runtime.activate: reload, and restart only when a restart setting changed.
        if any(self.world.fixes[f]["requires"] == "restart" for f in self.written ^ self.active):
            self.restarts += 1
            self.log.append("RESTART")
            if self.number in self.world.start_fails or (self.number, self.restarts) in self.world.start_fail_at:
                # Like runtime.activate when PostgreSQL does not come back after the restart.
                from services.sandbox_poc.runtime import SandboxStartError
                self.down = True
                raise SandboxStartError("PostgreSQL failed to start after restart: the server "
                                        "reported a fatal startup error")
        else:
            self.log.append("RELOAD")
        self.active = set(self.written)

    def health(self):
        return True

    def close(self):
        self.closed = True
        return {"verified": self.number not in self.world.cleanup_fails, "run_id": self.run_id}


class World:
    """fixes: {fix_id: {risk, requires, dependencies, needs, setting}}."""

    def __init__(self, **fixes):
        self.fixes = {}
        for fid, spec in fixes.items():
            risk, requires, *rest = spec
            self.fixes[fid] = {"risk": risk, "requires": requires, "dependencies": list(rest[0]) if rest else [],
                               "needs": rest[1] if len(rest) > 1 else None,
                               "setting": rest[2] if len(rest) > 2 else fid.removeprefix("fix-")}
        self.individual = {}      # fix_id -> status of its own test, or an exception to raise
        self.prepare_errors = {}  # fix_id -> exception raised while preparing it (no sandbox)
        self.apply_errors = set()  # (combined sandbox number, fix_id)
        self.verify_fails = set()  # (number or "*", fix_id), or ("restart", fix_id): only after a restart
        self.rollback_stuck = set()
        self.cleanup_fails = set()
        self.start_fails = set()   # combined sandbox numbers whose restart does not come back
        self.start_fail_at = set()  # (sandbox number, nth restart) that does not come back
        self.runtimes, self.verified, self.recorded, self.events = [], [], [], []
        self.ran, self.prepared, self.gate = [], [], None

    def control(self, fid):
        return "c:" + fid

    def review(self, fid):
        f = self.fixes[fid]
        return {"fix_id": fid, "spec_id": self.control(fid), "setting": f["setting"],
                "operational_risk": f["risk"], "requires": f["requires"], "dependencies": list(f["dependencies"])}

    def request(self, fid):
        return Request(snapshot=SOURCE, spec_set_hash="h", policy_profile_sha256=None, control_id=self.control(fid))

    def requests(self, *fids):
        return [self.request(f) for f in (fids or self.fixes)]

    def assess(self, snap):
        active = set(snap["active"])
        return {"findings": {self.control(fid): {"status": "PASS" if fid in active and (
            f["needs"] is None or f["needs"] in active) else "FAIL"} for fid, f in self.fixes.items()}}

    def prepare(self, request):
        """SandboxService.prepare: the fix unit, rendered SQL and risk review; no sandbox."""
        fid = request.control_id.removeprefix("c:")
        self.prepared.append(fid)
        if self.gate is not None:
            assert self.gate.wait(20)
        if fid in self.prepare_errors:
            raise self.prepare_errors[fid]
        return {"status": "PREPARED",
                "fix_unit": {"fix_id": fid, "spec_id": request.control_id,
                             "apply": {"param": self.fixes[fid]["setting"], "value": "on"}},
                "risk_review": self.review(fid),
                "rendered_apply_sql": "APPLY " + fid, "rendered_rollback_sql": "ROLLBACK " + fid}

    def run(self, request):
        fid = request.control_id.removeprefix("c:")
        self.ran.append(fid)
        if self.gate is not None:
            assert self.gate.wait(20)
        outcome = self.individual.get(fid, "VERIFIED")
        if isinstance(outcome, Exception):
            raise outcome
        result = {"status": outcome, "run_id": "run-" + fid,
                  "fix_unit": {"fix_id": fid, "spec_id": request.control_id,
                               "apply": {"param": self.fixes[fid]["setting"], "value": "on"}},
                  "risk_review": self.review(fid),
                  "rendered_apply_sql": "APPLY " + fid, "rendered_rollback_sql": "ROLLBACK " + fid}
        if outcome != "VERIFIED":
            result["attempts"] = [{"error": "health check failed"}]
        return result

    def factory(self):
        self.runtimes.append(Runtime(self, len(self.runtimes) + 1))
        return self.runtimes[-1]

    def verify(self, runtime, control, name, value, phase):
        fid = control.removeprefix("c:")
        self.verified.append((runtime.number, fid, runtime.restarts))
        failed = ((runtime.number, fid) in self.verify_fails or ("*", fid) in self.verify_fails
                  or (runtime.restarts and ("restart", fid) in self.verify_fails))
        return {"passed": not failed}

    def service(self):
        fake_engine = SimpleNamespace(specs=[], spec_set_hash="h", hashes={}, policy_pin=None,
                                      collect=lambda runtime: {"baseline": {"gaps": []},
                                                               "active": sorted(runtime.active)},
                                      assess=self.assess, gapped_settings=lambda findings: [])
        return SimpleNamespace(validate_handoff=lambda request: fake_engine, run=self.run,
                               prepare=self.prepare, runtime_factory=self.factory)


def fake_folder(handoff, prepared, step, record, engine, *, prior_snapshot, applied_snapshot, package_run_id,
                position, total, client_impact=False, single=None):
    """build_combined_fix_files with its batch-supplied fields; review_bundle is tested elsewhere."""
    assert record["status"] == "VERIFIED" and step["fix_id"] == prepared["fix_unit"]["fix_id"]
    # Real per-fix folders always carry the database name; the package needs it.
    config = {"fix_id": prepared["fix_unit"]["fix_id"], "database": "appdb", "run_id": record["run_id"],
              "combined_run_id": package_run_id, "client_impact": client_impact,
              "single_test": (single or {}).get("run_id")}
    return {"fix.json": json.dumps(config).encode(), "manifest.json": json.dumps({"files": {}}).encode()}


def fake_bundle(handoff, result, engine):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        # Real per-fix bundles always carry the database name (review_bundle); the package needs it.
        archive.writestr("fix.json", json.dumps({"fix_id": result["fix_unit"]["fix_id"], "database": "appdb"}))
        archive.writestr("manifest.json", json.dumps({"files": {}}))
    return buffer.getvalue()


@pytest.fixture
def faked(monkeypatch):
    """Everything outside the batch logic is faked; returns a function that installs a world."""
    def install(world, record_history=True):
        monkeypatch.setattr(batch_module, "build_review_bundle", fake_bundle)
        monkeypatch.setattr(batch_module, "build_combined_fix_files", fake_folder)
        monkeypatch.setattr(batch_module, "is_fixture", lambda result: False)
        if record_history:
            monkeypatch.setattr(batch_module.history, "record", lambda *args: world.recorded.append(args[1]))
        monkeypatch.setattr(batch_module, "reconstruction_plan",
                            lambda snap, specs: {"names": [], "signature": {"settings": {}}})
        monkeypatch.setattr(batch_module, "reconstruct", lambda runtime, plan: None)
        monkeypatch.setattr(batch_module, "signature", lambda snap, names: {"settings": {}})
        monkeypatch.setattr(batch_module, "_profile", lambda engine, snap, request, scopes, proposals:
                            world.review(request.control_id.removeprefix("c:")))
        monkeypatch.setattr("services.sandbox_poc.evidence_capture.verify_runtime", world.verify)
        return world
    return install


def run(world, *fids, **kwargs):
    return batch_module.run_batch(world.requests(*fids), world.service(), progress=world.events.append, **kwargs)


def statuses(output):
    return {f["fix_id"]: (f["status"], f["stage"]) for f in output["fixes"]}


def folders(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return sorted({name.split("/")[0] for name in archive.namelist() if "/" in name})


def texts(world):
    return [e["text"] for e in world.events if e.get("text")]


def ten_fixes():
    fixes = {f"fix-s{i:02d}": ("low" if i % 2 else "medium", "reload") for i in range(1, 9)}
    fixes.update({"fix-listen": ("high", "restart"), "fix-collector": ("high", "restart")})
    return World(**fixes)


# ---------------------------------------------------------------------------
# 1. No six-fix limit
# ---------------------------------------------------------------------------

class TestNoLimit:
    def test_ten_fixes_are_accepted_and_proven_together(self, faked):
        world = faked(ten_fixes())
        output, data = run(world)
        assert output["status"] == "VERIFIED", output
        assert len(output["fixes"]) == 10 and all(f == ("PASSED", "combined") for f in statuses(output).values())
        assert folders(data) == sorted(world.fixes)
        assert len(world.runtimes) == 1 and all(r.closed for r in world.runtimes)
        # Melvin, 12 Nov: combined first. All passed together, so no fix ran a test of its own.
        assert output["individual_runs"] == [] and world.ran == []
        assert sorted(world.prepared) == sorted(world.fixes)

    def test_one_fix_is_enough_and_none_is_refused(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload")}))
        output, data = run(world)
        assert output["status"] == "VERIFIED" and folders(data) == ["fix-a"]
        with pytest.raises(ContractError, match="at least one fix"):
            batch_module.run_batch([], world.service())

    def test_a_duplicate_fix_is_refused_before_anything_runs(self, faked):
        world = faked(ten_fixes())
        with pytest.raises(ContractError, match="Duplicate fixes"):
            batch_module.run_batch(world.requests("fix-s01", "fix-s02", "fix-s01"), world.service())
        assert world.ran == [] and world.runtimes == []

    def test_request_model_has_no_upper_number(self):
        common = {"snapshot_id": "snap-abc", "template_version": 1, "evidence_ids": ["d"]}
        many = [PrepareRequest(**common, control_id=f"{B}:3.1.{i}") for i in range(2, 27)]
        assert len(routes.BatchRequest(fixes=many).fixes) == 25
        assert len(routes.BatchRequest(fixes=many[:1]).fixes) == 1
        assert routes.BatchRequest(fixes=many, requested_order=[f"fix-{i}" for i in range(25)])
        with pytest.raises(ValueError):
            routes.BatchRequest(fixes=[])
        with pytest.raises(ValueError, match="Duplicate fixes"):
            routes.BatchRequest(fixes=many + many[:1])

    def test_a_fix_the_plan_does_not_offer_is_refused(self, engine, planted, monkeypatch):  # noqa: F811
        monkeypatch.setattr(profiles, "resolve_profile", lambda records, specs, ref: engine.policy)
        service, requests, runtimes = object_service(engine, planted, proposals_for(engine, planted)[:2])
        unknown = requests[1].model_copy(update={"object_fix_id": "fix-4.4-role_nologin-0000000000"})
        for fix_all in (False, True):
            with pytest.raises(ContractError):
                batch_module.run_batch([requests[0], unknown], service, fix_all=fix_all)
        assert runtimes == []


# ---------------------------------------------------------------------------
# 2. Two phases, one restart, dependency verified after the restart
# ---------------------------------------------------------------------------

class TestPhaseOrder:
    def test_no_restart_first_low_risk_first_then_restart_fixes(self, faked):
        world = faked(World(**{"fix-z": ("low", "restart"), "fix-high": ("high", "reload"),
                               "fix-b": ("low", "reload"), "fix-a": ("low", "reload"),
                               "fix-m": ("medium", "reload"), "fix-r": ("high", "restart")}))
        output, _ = run(world)
        assert output["status"] == "VERIFIED", output
        # Phase 1 by risk then fix id; phase 2 the same; a low-risk restart fix still waits.
        assert output["recommended_order"] == ["fix-a", "fix-b", "fix-m", "fix-high", "fix-z", "fix-r"]
        assert output["phases"] == {"1": ["fix-a", "fix-b", "fix-m", "fix-high"], "2": ["fix-z", "fix-r"]}
        assert [s["fix_id"] for s in output["combined_test"]["steps"]] == output["recommended_order"]
        assert [s["phase"] for s in output["combined_test"]["steps"]] == [1, 1, 1, 1, 2, 2]
        assert output["order_source"] == "RECOMMENDED"

    def test_restart_fixes_are_written_together_and_the_sandbox_restarts_once(self, faked):
        world = faked(ten_fixes())
        output, _ = run(world)
        runtime = world.runtimes[0]
        applies = [i for i, s in enumerate(runtime.log) if s.startswith("APPLY")]
        first_restart = runtime.log.index("RESTART")
        # Every fix is written before the one restart; phase 1 only ever reloads.
        assert all(i < first_restart for i in applies) and len(applies) == 10
        assert runtime.log[applies[-2]:first_restart] == ["APPLY fix-collector", "APPLY fix-listen"]
        assert "RESTART" not in runtime.log[:applies[-2]]
        assert output["combined_test"]["restarts"] == 1
        # One restart to apply, one to undo both restart fixes together.
        assert runtime.log.count("RESTART") == 2 and runtime.restarts == 2
        rollback = output["combined_test"]["rollback"]
        assert [r["fix_id"] for r in rollback] == list(reversed(output["recommended_order"]))
        assert all(r["verified"] for r in rollback)
        assert [r.get("joint_restart", False) for r in rollback] == [True, True] + [False] * 8
        # Restart fixes are checked only after the restart.
        assert all(restarts == 1 for _, fid, restarts in world.verified if fid in ("fix-collector", "fix-listen"))

    def test_a_batch_without_restart_fixes_never_restarts(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("medium", "reload")}))
        output, _ = run(world)
        assert output["status"] == "VERIFIED" and world.runtimes[0].restarts == 0
        assert "restarts" not in output["combined_test"] and output["phases"]["2"] == []

    def test_a_dependent_fix_is_written_in_phase_1_and_verified_after_the_restart(self, faked):
        # log_truncate_on_rotation only takes effect with logging_collector on.
        world = faked(World(**{"fix-collector": ("high", "restart"),
                               "fix-truncate": ("high", "reload", ["fix-collector"], "fix-collector"),
                               "fix-plain": ("low", "reload")}))
        output, data = run(world)
        assert output["status"] == "VERIFIED", output
        assert output["recommended_order"] == ["fix-plain", "fix-truncate", "fix-collector"]
        steps = {s["fix_id"]: s for s in output["combined_test"]["steps"]}
        # In phase 1 its own control is not PASS yet (collector off): that check is deferred.
        assert steps["fix-truncate"]["assessment"]["findings"]["c:fix-truncate"]["status"] == "FAIL"
        assert steps["fix-truncate"]["verification"] == "AFTER_RESTART"
        assert steps["fix-truncate"]["verified_after_restart"]["status"] == "PASS"
        assert "verification" not in steps["fix-plain"] and "verified_after_restart" not in steps["fix-plain"]
        # Its last check ran after the one restart.
        assert [r for _, fid, r in world.verified if fid == "fix-truncate"] == [0, 1]
        assert any("logging_collector is on" in t for t in texts(world))
        assert folders(data) == ["fix-collector", "fix-plain", "fix-truncate"]

    def test_a_dependent_fix_that_fails_after_the_restart_is_left_out(self, faked):
        world = faked(World(**{"fix-collector": ("high", "restart"),
                               "fix-truncate": ("high", "reload", ["fix-collector"], "fix-collector"),
                               "fix-plain": ("low", "reload")}))
        world.verify_fails.add(("restart", "fix-truncate"))
        output, data = run(world)
        assert output["status"] == "PARTIAL"
        assert statuses(output)["fix-truncate"] == ("FAILED", "combined")
        assert "logging_collector" in output["fixes"][1]["reason"]
        assert output["combined_attempts"][0]["failed_fix_id"] == "fix-truncate"
        assert folders(data) == ["fix-collector", "fix-plain"]

    def test_without_its_prerequisite_in_the_batch_the_fix_is_verified_at_once(self, faked):
        world = faked(World(**{"fix-collector": ("high", "restart"),
                               "fix-truncate": ("high", "reload", ["fix-collector"]),
                               "fix-plain": ("low", "reload")}))
        world.prepare_errors["fix-collector"] = ContractError("The selected supported control must be FAIL")
        output, _ = run(world)
        assert output["status"] == "PARTIAL" and output["recommended_order"] == ["fix-plain", "fix-truncate"]
        assert all("verification" not in s for s in output["combined_test"]["steps"])
        assert world.runtimes[0].restarts == 0

    def test_a_selected_order_may_not_put_a_restart_fix_first(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-r": ("high", "restart")}))
        output, _ = run(world, requested_order=["fix-a", "fix-r"])
        assert output["status"] == "VERIFIED" and output["order_source"] == "DBA_SELECTED"
        with pytest.raises(ContractError, match="no restart before"):
            run(faked(World(**{"fix-a": ("low", "reload"), "fix-r": ("high", "restart")})),
                requested_order=["fix-r", "fix-a"])
        with pytest.raises(ContractError, match="every fix exactly once"):
            run(faked(World(**{"fix-a": ("low", "reload"), "fix-r": ("high", "restart")})),
                requested_order=["fix-a"])


class TestSharedOrdering:
    """planning.recommend_order: the fix plan and the batch use the same phase key."""

    @staticmethod
    def fix(fix_id, risk, requires=None, dependencies=()):
        item = {"fix_id": fix_id, "setting": fix_id, "operational_risk": risk, "dependencies": list(dependencies)}
        if requires:
            item["requires"] = requires
        return item

    def test_phase_then_risk_then_fix_id(self):
        fixes = [self.fix("r-low", "low", "restart"), self.fix("b", "high", "reload"), self.fix("a", "high", "none"),
                 self.fix("c", "low"), self.fix("r-high", "high", "restart")]
        assert [f["fix_id"] for f in planning.recommend_order(fixes)] == ["c", "a", "b", "r-low", "r-high"]
        assert [planning.fix_phase(f) for f in fixes] == [2, 1, 1, 1, 2]

    def test_a_dependency_on_a_restart_fix_no_longer_moves_the_fix_behind_it(self):
        collector = self.fix("fix-logging_collector", "high", "restart")
        truncate = self.fix("fix-log_truncate_on_rotation", "high", "reload", ["fix-logging_collector"])
        order = [f["fix_id"] for f in planning.recommend_order([collector, truncate])]
        assert order == ["fix-log_truncate_on_rotation", "fix-logging_collector"]

    def test_a_dependency_in_the_same_phase_still_orders(self):
        first, second = self.fix("z", "high", "reload"), self.fix("a", "low", "reload", ["z"])
        assert [f["fix_id"] for f in planning.recommend_order([second, first])] == ["z", "a"]

    def test_a_missing_dependency_is_refused_unless_the_batch_left_it_out(self):
        lonely = self.fix("a", "low", "reload", ["gone"])
        with pytest.raises(ContractError, match="missing or cyclic"):
            planning.recommend_order([lonely])
        assert planning.recommend_order([lonely], allow_missing_dependencies=True) == [lonely]

    def test_real_specs_logging_collector_is_a_restart_fix_after_its_dependents(self, engine, snapshot):  # noqa: F811
        snap = copy.deepcopy(snapshot)
        rows = setting_rows(snap)
        rows["logging_collector"].update(setting="off", context="postmaster")
        rows["log_truncate_on_rotation"]["setting"] = "off"
        truncate = planning.risk_review(engine, snap, f"{B}:3.1.7")
        collector = planning.risk_review(engine, snap, f"{B}:3.1.3")
        assert collector["requires"] == "restart" and truncate["requires"] == "reload"
        # The dependency is kept (it now means: verify after the restart), not the old order.
        assert truncate["dependencies"] == ["fix-logging_collector"]
        order = [f["fix_id"] for f in planning.recommend_order([collector, truncate])]
        assert order == ["fix-log_truncate_on_rotation", "fix-logging_collector"]


# ---------------------------------------------------------------------------
# 3. A failing fix is left out; the rest continue
# ---------------------------------------------------------------------------

class TestFailedFixesAreLeftOut:
    def test_an_individual_failure_no_longer_stops_the_batch(self, faked):
        world = faked(ten_fixes())
        world.verify_fails.add(("*", "fix-listen"))  # fails in the combined test ...
        world.individual["fix-listen"] = "FAILED"    # ... and on its own
        world.prepare_errors["fix-s03"] = ContractError("The selected supported control must be FAIL")
        output, data = run(world)
        assert output["status"] == "PARTIAL"
        assert world.ran == ["fix-listen"]  # only the fix that failed together got its own test
        by_id = {f["fix_id"]: f for f in output["fixes"]}
        assert (by_id["fix-listen"]["status"], by_id["fix-listen"]["stage"]) == ("FAILED", "individual")
        assert by_id["fix-listen"]["reason"] == "health check failed"
        assert (by_id["fix-s03"]["status"], by_id["fix-s03"]["stage"]) == ("FAILED", "preparation")
        assert "must be FAIL" in by_id["fix-s03"]["reason"]
        assert output["individual_runs"] == [{"run_id": "run-fix-listen", "fix_id": "fix-listen", "status": "FAILED"}]
        passed = sorted(f for f, s in statuses(output).items() if s == ("PASSED", "combined"))
        assert len(passed) == 8 and folders(data) == passed == sorted(output["recommended_order"])
        assert [u["fix_id"] for u in output["fix_units"]] == output["recommended_order"]
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            readme = archive.read("README.txt").decode()
            evidence = json.loads(archive.read("combined-evidence.json"))
        assert readme.startswith("PARTIAL RESULT") and "fix-listen: FAILED (individual): health check failed" in readme
        assert "All selected fixes passed" not in readme
        assert evidence["status"] == "PARTIAL" and evidence["fixes"] == output["fixes"]
        assert any("fix-listen FAILED on its own too and was left out (health check failed)" in t for t in texts(world))
        assert "Fix 3 of 10 could not be prepared and was left out: s03 (The selected supported control must be FAIL)." in texts(world)

    @pytest.mark.parametrize("where", ["preparation", "individual"])
    def test_an_unexpected_error_is_reported_by_type_only(self, faked, where):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload")}))
        error = RuntimeError("dsn=postgresql://user:secret@host/db")
        if where == "preparation":
            world.prepare_errors["fix-b"] = error
        else:
            world.verify_fails.add(("*", "fix-b"))
            world.individual["fix-b"] = error
        output, _ = run(world)
        assert output["status"] == "PARTIAL"
        reason = output["fixes"][1]["reason"]
        assert output["fixes"][1]["stage"] == where
        assert "RuntimeError" in reason and "secret" not in json.dumps(output)
        assert "secret" not in json.dumps(world.events)

    def test_no_fix_that_can_be_prepared_is_failed_without_a_combined_sandbox(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload")}))
        world.prepare_errors.update({"fix-a": ContractError("Gapped controls cannot establish regression coverage"),
                                     "fix-b": ContractError("Approved template is outside the supported setting action")})
        output, data = run(world)
        assert output["status"] == "FAILED" and data is None and world.runtimes == [] and world.ran == []
        assert "combined_test" not in output and set(statuses(output).values()) == {("FAILED", "preparation")}
        assert "No selected fix could be prepared" in output["reason"]
        assert output["schema_version"] == "sandbox-batch-v1"

    def test_a_combined_failure_at_step_k_is_retried_without_k(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload"),
                               "fix-c": ("medium", "reload"), "fix-r": ("high", "restart")}))
        world.verify_fails.add((1, "fix-b"))
        output, data = run(world)
        assert output["status"] == "PARTIAL"
        assert statuses(output) == {"fix-a": ("PASSED", "combined"), "fix-b": ("FAILED", "combined"),
                                    "fix-c": ("PASSED", "combined"), "fix-r": ("PASSED", "combined")}
        # It passed its own test (the default here), so it works alone but not with the others.
        assert output["fixes"][1]["reason"] == ("It passes its own test, but not together with the other fixes; in "
                                                "the combined test: Combined target, regression or functional gate failed")
        assert world.ran == ["fix-b"] and output["individual_runs"] == [
            {"run_id": "run-fix-b", "fix_id": "fix-b", "status": "VERIFIED"}]
        attempts = output["combined_attempts"]
        assert [a["status"] for a in attempts] == ["FAILED", "VERIFIED"]
        assert attempts[0]["failed_fix_id"] == "fix-b" and attempts[0]["failed_stage"] == "phase 1"
        # The failed attempt was undone exactly and its sandbox removed before the retry.
        assert attempts[0]["rollback"] == [{"fix_id": "fix-b", "verified": True}, {"fix_id": "fix-a", "verified": True}]
        assert len(world.runtimes) == 2 and all(r.closed for r in world.runtimes)
        assert "APPLY fix-b" not in world.runtimes[1].log
        assert output["combined_test"]["run_id"] == "combined-2" and output["combined_test"]["status"] == "VERIFIED"
        assert folders(data) == ["fix-a", "fix-c", "fix-r"]
        assert any("fix-b FAILED in the combined test and was left out" in t for t in texts(world))
        assert any(t.startswith("Combined test (retry 1 of 3)") for t in texts(world))

    def test_a_restart_fix_failing_after_the_restart_is_left_out(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-r1": ("high", "restart"),
                               "fix-r2": ("high", "restart")}))
        world.verify_fails.add((1, "fix-r1"))
        output, data = run(world)
        assert output["status"] == "PARTIAL" and statuses(output)["fix-r1"] == ("FAILED", "combined")
        assert output["combined_attempts"][0]["failed_stage"] == "phase 2"
        assert folders(data) == ["fix-a", "fix-r2"]

    def test_three_retries_then_the_rest_is_proven(self, faked):
        world = faked(World(**{f"fix-{c}": ("low", "reload") for c in "abcde"}))
        world.verify_fails.update({("*", "fix-a"), ("*", "fix-b"), ("*", "fix-c")})
        output, data = run(world)
        assert output["status"] == "PARTIAL" and len(world.runtimes) == 4
        assert folders(data) == ["fix-d", "fix-e"]

    def test_at_most_three_retries_then_stop(self, faked):
        world = faked(World(**{f"fix-{c}": ("low", "reload") for c in "abcdef"}))
        world.verify_fails.update({("*", f"fix-{c}") for c in "abcd"})
        output, data = run(world)
        # First attempt plus three retries, never a fifth sandbox.
        assert len(world.runtimes) == 4 and all(r.closed for r in world.runtimes)
        assert output["status"] == "FAILED" and data is None
        assert len(output["combined_attempts"]) == 4
        got = statuses(output)
        assert all(got[f"fix-{c}"] == ("FAILED", "combined") for c in "abcdef")
        assert "stopped after 3 retries" in output["fixes"][-1]["reason"]

    def test_a_combined_apply_error_is_attributed_to_its_fix(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload")}))
        world.apply_errors.add((1, "fix-a"))
        output, data = run(world)
        assert output["status"] == "PARTIAL" and statuses(output)["fix-a"] == ("FAILED", "combined")
        assert folders(data) == ["fix-b"]

    @pytest.mark.parametrize("phase", ["reload", "restart"])
    def test_a_rollback_failure_is_a_hard_failure_never_partial(self, faked, phase):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", phase), "fix-c": ("low", "reload")}))
        world.rollback_stuck.add((1, "fix-b"))
        output, data = run(world)
        assert output["status"] == "FAILED" and data is None
        assert output["combined_test"]["rollback_error"] == "Combined exact rollback failed"
        assert output["combined_test"]["hard_failure"] is True
        assert len(world.runtimes) == 1 and world.runtimes[0].closed  # no retry
        assert all(status == ("FAILED", "combined") for status in statuses(output).values())

    def test_a_rollback_failure_after_a_failed_step_is_not_retried(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload")}))
        world.verify_fails.add((1, "fix-b"))
        world.rollback_stuck.add((1, "fix-a"))
        output, data = run(world)
        assert output["status"] == "FAILED" and data is None and len(world.runtimes) == 1

    def test_a_cleanup_failure_is_a_hard_failure_never_partial(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload")}))
        world.cleanup_fails.add(1)
        output, data = run(world)
        assert output["status"] == "CLEANUP_FAILED" and data is None and len(world.runtimes) == 1

    def test_an_individual_cleanup_failure_stops_the_batch(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload"), "fix-c": ("low", "reload")}))
        world.verify_fails.add((1, "fix-b"))
        world.individual["fix-b"] = "CLEANUP_FAILED"
        output, data = run(world)
        assert output["status"] == "CLEANUP_FAILED" and data is None
        # Its own test ran only after the combined failure; nothing ran after the cleanup failure.
        assert world.ran == ["fix-b"] and len(world.runtimes) == 1
        got = statuses(output)
        assert got["fix-b"] == ("FAILED", "individual") and got["fix-a"] == got["fix-c"] == ("FAILED", "combined")
        assert "could not be removed" in output["fixes"][0]["reason"]


# ---------------------------------------------------------------------------
# Conflicts: refused, or NOT_ELIGIBLE in a fix-all batch
# ---------------------------------------------------------------------------

def object_service(engine, snapshot, proposals):  # noqa: F811
    """test_object_sandbox.batch_service for a chosen list of real, evidence-derived proposals."""
    from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
    from services.sandbox_poc.service import SandboxService
    from scripts.sandbox_poc import demo_template
    effects = [effect_for(p) for p in proposals]
    runtimes = []

    def factory():
        runtimes.append(ObjectRuntime(snapshot, len(runtimes) + 1, effects))
        return runtimes[-1]

    templates = {p["fix_type"]: object_template(p["fix_type"]) for p in proposals}
    evidence = [{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}]
    refs = {name: TemplateReference(registry_name=name, version=1, sha256=t.sha256, evidence=evidence)
            for name, t in templates.items()}
    service = SandboxService("unused", runtime_factory=factory,
                             registry_loader=lambda url, version, sha, docs, env, **kw: templates[kw["registry_name"]])
    setting = demo_template()
    base = build_handoff(engine, snapshot, TemplateReference(version=setting.version, sha256=setting.sha256,
                                                             evidence=evidence)).model_dump()
    requests = [SandboxHandoff(**{**base, "control_id": p["spec_id"], "object_fix_id": p["fix_id"],
                                  "template_ref": refs[p["fix_type"]].model_dump()}) for p in proposals]
    return service, requests, runtimes


class TestConflicts:
    def test_two_fixes_on_one_setting_keep_the_lower_risk_one(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-high": ("high", "reload", [], None, "log_x"),
                               "fix-low": ("low", "reload", [], None, "log_x")}))
        output, data = run(world, fix_all=True)
        assert output["status"] == "PARTIAL"
        assert statuses(output) == {"fix-a": ("PASSED", "combined"), "fix-high": ("NOT_ELIGIBLE", "planning"),
                                    "fix-low": ("PASSED", "combined")}
        reason = output["fixes"][1]["reason"]
        assert "setting log_x" in reason and "fix-low" in reason
        assert "fix-high" not in world.ran  # never tested, not even on its own
        assert folders(data) == ["fix-a", "fix-low"]

    def test_outside_fix_all_the_same_conflict_still_refuses_the_batch(self, faked):
        world = faked(World(**{"fix-high": ("high", "reload", [], None, "log_x"),
                               "fix-low": ("low", "reload", [], None, "log_x")}))
        with pytest.raises(ContractError, match="same setting"):
            run(world)

    def test_the_same_object_change_under_two_controls(self, engine, planted, monkeypatch, tmp_path):  # noqa: F811
        from services.sandbox_poc import object_fixes
        monkeypatch.setattr(profiles, "resolve_profile", lambda records, specs, ref: engine.policy)
        monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
        monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
        same = [p for p in object_fixes.proposals(engine, planted, engine.policy_pin)
                if p["fix_type"] == "role_drop_attribute"
                and p["target"] == {"role": "app_admin", "attribute": "SUPERUSER"}]
        assert sorted(p["spec_id"] for p in same) == [f"{B}:4.3", f"{B}:4.9"]
        chosen = same + proposals_for(engine, planted)[:1]
        service, requests, runtimes = object_service(engine, copy.deepcopy(planted), chosen)
        with pytest.raises(ContractError, match="same object attribute"):
            batch_module.run_batch(requests, service)
        assert runtimes == []
        output, data = batch_module.run_batch(requests, service, fix_all=True)
        assert output["status"] == "PARTIAL", output.get("combined_test", {}).get("reason") or output
        got = {f["fix_id"]: f for f in output["fixes"]}
        kept, dropped = sorted(p["fix_id"] for p in same)  # equal risk: the earlier fix id is kept
        assert got[kept]["status"] == "PASSED" and got[dropped]["status"] == "NOT_ELIGIBLE"
        assert kept in got[dropped]["reason"] and "SUPERUSER" in got[dropped]["reason"]
        # One combined sandbox and no single test (12 Nov): the dropped fix never ran.
        assert len(runtimes) == 1 and all(r.closed for r in runtimes) and output["individual_runs"] == []
        assert folders(data) == sorted([kept, chosen[2]["fix_id"]])


# ---------------------------------------------------------------------------
# Progress lines and the job's counters
# ---------------------------------------------------------------------------

class TestProgress:
    def test_plain_english_lines_in_order(self, faked):
        world = faked(ten_fixes())
        world.verify_fails.add(("*", "fix-listen"))
        world.individual["fix-listen"] = "FAILED"
        run(world)
        lines = texts(world)
        assert lines[0] == "Preparing 10 fixes (no sandbox needed)…"
        assert "Preparing fix 1 of 10: s01 (low risk)…" in lines
        assert "Preparing fix 9 of 10: listen (high risk)…" in lines
        assert not any("on its own:" in t for t in lines)  # no fix is tested alone up front
        assert "Combined test, phase 1 (no restart): applying 3 of 8: s05 (low risk)…" in lines
        assert "Combined test, phase 2: restarting the sandbox database once for 2 restart fixes…" in lines
        assert "listen FAILED in the combined test; testing it on its own to find out why…" in lines
        assert "listen also FAILED on its own (health check failed)." in lines
        assert ("fix-listen FAILED on its own too and was left out (health check failed). "
                "Testing the others together again…") in lines
        assert "Combined test (retry 1 of 3), phase 2: restarting the sandbox database once for 1 restart fix…" in lines
        assert "Combined test (retry 1 of 3): undoing all fixes and checking the copy is back as before…" in lines
        assert lines[-2] == "Building the package…"
        assert lines[-1] == "Finished: PARTIAL. 9 of 10 fixes passed together and are in the package."
        order = [lines.index(t) for t in ("Preparing fix 1 of 10: s01 (low risk)…",
                                          "Combined test, phase 1 (no restart): applying 3 of 8: s05 (low risk)…",
                                          "Combined test, phase 2: restarting the sandbox database once for 2 restart fixes…",
                                          "Combined test: undoing all fixes and checking the copy is back as before…",
                                          "listen FAILED in the combined test; testing it on its own to find out why…",
                                          "Combined test (retry 1 of 3), phase 1 (no restart): applying 3 of 8: s05 (low risk)…",
                                          "Building the package…")]
        assert order == sorted(order)

    def test_a_broken_progress_callback_never_changes_the_verdict(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("high", "restart")}))

        def broken(event):
            raise RuntimeError("UI went away")
        output, data = batch_module.run_batch(world.requests(), world.service(), progress=broken)
        assert output["status"] == "VERIFIED" and data

    def test_job_counts_and_estimates_from_measured_combined_steps(self, faked):
        # 12 Nov: no fix is tested alone up front, so the estimate comes from the combined
        # steps; a single test (only after a combined failure) adds itself and a retry.
        world = faked(ten_fixes())
        world.verify_fails.add((1, "fix-s02"))  # fails together once; passes on its own
        clock = {"now": 100.0}
        job = batch_jobs.BatchJob("b-1", 10, clock=lambda: clock["now"])
        seen = []

        def progress(event):
            # Preparing a fix takes 1 s, every combined step 2 s, a single test 10 s.
            clock["now"] += {"prepare_done": 1, "combined_step": 2, "combined_check": 2,
                             "individual_done": 10}.get(event["kind"], 0)
            job.event(event)
            seen.append((event["kind"], job.progress()))
        assert job.progress()["estimate_seconds"] is None and job.progress()["step_text"] == "Starting…"
        output, _ = batch_module.run_batch(world.requests(), world.service(), progress=progress)
        job.finish(output["status"], output)
        views = [p for _, p in seen]
        assert all(a["done"] <= b["done"] for a, b in zip(views, views[1:]))
        assert all(p["done"] <= p["total"] and p["status"] == "RUNNING" for p in views)
        # While preparing nothing has been timed in a sandbox yet: no estimate, no single tests counted.
        preparing = [p for kind, p in seen if kind in ("plan", "prepare_start", "prepare_done")]
        assert all(p["estimate_seconds"] is None and p["phase"] == "prepare" for p in preparing)
        assert preparing[-1]["done"] == 10 and preparing[-1]["total"] == 10 + 10 + 1 + 1
        # First combined step timed (2 s): 9 steps left, doubled for the undo, plus one for the package.
        first_step = next(p for kind, p in seen if kind == "combined_step")
        assert first_step["estimate_seconds"] == 9 * 2 * 2 + 2 and first_step["done"] == 11
        # fix-s02 failed at step 5; its own test starts: the whole attempt applied and undone
        # (no single test timed yet), then a retry of the other 9, plus the package.
        single = next(p for kind, p in seen if kind == "individual_start")
        assert single["phase"] == "individual" and single["current_fix"] == "fix-s02"
        assert single["total"] == 10 + 1 + 5 + 1 + 1  # prepared, one single test, 5 steps run, undo, package
        assert single["estimate_seconds"] == 2 + (10 * 2 * 2) + (9 * 2 * 2 + 2)
        assert output["individual_runs"] == [{"run_id": "run-fix-s02", "fix_id": "fix-s02", "status": "VERIFIED"}]
        final = job.view()
        assert final["status"] == "PARTIAL" and final["done"] == final["total"] and final["estimate_seconds"] == 0
        assert final["result"] is output and final["current_fix"] is None
        assert {"at", "text"} <= set(final["steps"][0])
        # The combined attempt's own FAILED line has no fix; the left-out line names fix-s02.
        failed = [s for s in final["steps"] if s.get("status") == "FAILED"]
        assert "fix_id" not in failed[0] and failed[0]["text"].startswith("Combined test did not pass")
        assert [s["fix_id"] for s in failed[1:]] == ["fix-s02"]

    def test_a_batch_with_no_single_test_still_gets_an_estimate(self):
        job = batch_jobs.BatchJob("b-2", 2, clock=lambda: 0.0)
        for event in ({"kind": "plan", "count": 2}, {"kind": "prepare_done", "status": "PASSED"},
                      {"kind": "prepare_done", "status": "PASSED"}, {"kind": "combined_start", "count": 2}):
            job.event(event)
        assert job.progress()["estimate_seconds"] is None
        job.clock = lambda: 3.0
        job.event({"kind": "combined_step"})
        assert job.progress()["estimate_seconds"] == 1 * 3 * 2 + 3
        assert job.progress()["total"] == 2 + 2 + 1 + 1


# ---------------------------------------------------------------------------
# 4. Background endpoint: returns at once, progress, 409, history, INTERRUPTED
# ---------------------------------------------------------------------------

BODY = {"snapshot_id": "snap-abc", "template_version": 1, "evidence_ids": ["d"]}


def body(*fids, **extra):
    return {"fixes": [{**BODY, "control_id": "c:" + f} for f in fids], **extra}


@pytest.fixture
def api(faked, monkeypatch, tmp_path):
    world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("medium", "reload"),
                           "fix-r": ("high", "restart")}), record_history=False)
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    monkeypatch.setattr(batch_jobs, "JOBS", batch_jobs.BatchJobs())
    monkeypatch.setattr(routes, "bundles", routes.BundleStore())

    def prepare(store, service, request):
        fid = request.control_id.removeprefix("c:")
        if fid not in world.fixes:
            raise ContractError("The selected supported control must be FAIL")
        return world.request(fid)
    monkeypatch.setattr(routes, "prepare_uploaded", prepare)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.get_service] = world.service
    app.dependency_overrides[routes.get_snapshot_store] = lambda: None
    return SimpleNamespace(world=world, client=TestClient(app))


def wait_for(client, batch_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        view = client.get(f"/api/v1/sandbox/batches/{batch_id}").json()
        if view["status"] != "RUNNING":
            return view
        time.sleep(0.02)
    raise AssertionError("batch did not finish")


class TestBackgroundEndpoint:
    def test_post_returns_at_once_and_get_shows_progress_then_the_result(self, api):
        api.world.gate = threading.Event()  # preparing a fix blocks until released
        started = time.monotonic()
        response = api.client.post("/api/v1/sandbox/batches", json=body("fix-a", "fix-b", "fix-r", fix_all=True))
        assert response.status_code == 202 and time.monotonic() - started < 5
        accepted = response.json()
        batch_id = accepted["batch_id"]
        assert accepted == {"batch_id": batch_id, "run_id": batch_id, "status": "RUNNING", "total_fixes": 3,
                            "not_eligible": [], "progress_url": f"/api/v1/sandbox/batches/{batch_id}"}
        try:
            deadline = time.monotonic() + 10
            while not api.world.prepared and time.monotonic() < deadline:
                time.sleep(0.01)
            running = api.client.get(accepted["progress_url"]).json()
            assert running["status"] == "RUNNING" and running["result"] is None
            assert set(running) == {"batch_id", "run_id", "status", "done", "total", "phase", "current_fix", "step",
                                    "step_text", "elapsed_seconds", "estimate_seconds", "steps", "result"}
            assert running["step_text"] == "Preparing fix 1 of 3: a (low risk)…"
            assert (running["done"], running["phase"], running["current_fix"]) == (0, "prepare", "fix-a")
            assert running["total"] == 3 + 3 + 1 + 1
            # Recorded as RUNNING in the history the moment it starts.
            listed = {r["run_id"]: r["status"] for r in api.client.get("/api/v1/history").json()["runs"]}
            assert listed[batch_id] == "RUNNING"
            # Only one batch at a time.
            again = api.client.post("/api/v1/sandbox/batches", json=body("fix-a"))
            assert again.status_code == 409 and "already running" in again.json()["detail"]
        finally:
            api.world.gate.set()
        done = wait_for(api.client, batch_id)
        assert done["status"] == "VERIFIED" and done["done"] == done["total"] and done["estimate_seconds"] == 0
        result = done["result"]
        assert result["run_id"] == batch_id and result["status"] == "VERIFIED"
        assert [f["status"] for f in result["fixes"]] == ["PASSED"] * 3
        assert result["review_bundle"] == {"status": "READY", "url": f"/api/v1/sandbox/runs/{batch_id}/bundle"}
        assert done["steps"][-1]["text"].startswith("Finished: VERIFIED.")
        assert any("restarting the sandbox database once" in s["text"] for s in done["steps"])
        assert result["individual_runs"] == [] and api.world.ran == []  # combined first: no single test
        # A finished batch is visible after a reload: history list, stored GET and bundle.
        listed = {r["run_id"]: r["status"] for r in api.client.get("/api/v1/history").json()["runs"]}
        assert listed[batch_id] == "VERIFIED"
        batch_jobs.JOBS.jobs.clear()
        stored = api.client.get(f"/api/v1/sandbox/batches/{batch_id}").json()
        assert stored["status"] == "VERIFIED" and stored["result"]["fixes"] == result["fixes"]
        assert stored["steps"] == done["steps"] and stored["done"] == stored["total"]
        routes.bundles = routes.BundleStore()
        bundle = api.client.get(result["review_bundle"]["url"])
        assert bundle.status_code == 200 and folders(bundle.content) == ["fix-a", "fix-b", "fix-r"]
        # And a new batch may start now.
        assert api.client.post("/api/v1/sandbox/batches", json=body("fix-a")).status_code == 202

    def test_a_partial_batch_is_reported_per_fix(self, api):
        api.world.verify_fails.add(("*", "fix-b"))
        api.world.individual["fix-b"] = "FAILED"
        accepted = api.client.post("/api/v1/sandbox/batches", json=body("fix-a", "fix-b", "fix-r")).json()
        done = wait_for(api.client, accepted["batch_id"])
        assert done["status"] == "PARTIAL"
        assert done["result"]["fixes"] == [
            {"fix_id": "fix-a", "status": "PASSED", "stage": "combined", "reason": None},
            {"fix_id": "fix-b", "status": "FAILED", "stage": "individual", "reason": "health check failed"},
            {"fix_id": "fix-r", "status": "PASSED", "stage": "combined", "reason": None}]
        assert history.get(accepted["batch_id"])["result"]["status"] == "PARTIAL"
        assert history.bundle(accepted["batch_id"]) is not None

    def test_an_unknown_or_duplicate_fix_is_refused_and_nothing_starts(self, api):
        unknown = api.client.post("/api/v1/sandbox/batches", json=body("fix-a", "fix-nope", fix_all=True))
        assert unknown.status_code == 422 and "must be FAIL" in unknown.json()["detail"]
        assert api.client.post("/api/v1/sandbox/batches", json=body("fix-a", "fix-a")).status_code == 422
        assert api.client.post("/api/v1/sandbox/batches", json={"fixes": []}).status_code == 422
        assert api.world.ran == [] and not batch_jobs.JOBS.busy()
        assert api.client.get("/api/v1/history").json()["runs"] == []

    def test_a_crashing_batch_ends_failed_and_frees_the_service(self, api, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("password=hunter2")
        monkeypatch.setattr(batch_module, "_combined_attempt", boom)
        accepted = api.client.post("/api/v1/sandbox/batches", json=body("fix-a")).json()
        done = wait_for(api.client, accepted["batch_id"])
        assert done["status"] == "FAILED" and "RuntimeError" in done["result"]["reason"]
        assert "hunter2" not in json.dumps(done)
        assert history.get(accepted["batch_id"])["result"]["status"] == "FAILED"
        assert not batch_jobs.JOBS.busy()

    def test_no_sandbox_screenshots_inside_a_background_batch(self, api, monkeypatch):
        monkeypatch.setenv("DBGUARD_SCREENSHOTS", "true")
        monkeypatch.setenv("DBGUARD_SCREENSHOT_MODE", "terminal")
        modes = []
        world = api.world

        def spy(original):
            def spying(*args):
                modes.append((original.__name__, tc.screenshot_mode(), tc.capture_suppressed()))
                return original(*args)
            return spying
        # Combined first (12 Nov): preparing, the combined sandbox and the single test of fix-a,
        # which fails in the first combined attempt, all run inside the batch thread.
        world.prepare, world.factory, world.run = spy(world.prepare), spy(world.factory), spy(world.run)
        world.verify_fails.add((1, "fix-a"))
        accepted = api.client.post("/api/v1/sandbox/batches", json=body("fix-a", "fix-r")).json()
        done = wait_for(api.client, accepted["batch_id"])
        assert done["status"] == "PARTIAL"
        assert [m[0] for m in modes] == ["prepare", "prepare", "factory", "run", "factory"]
        assert {m[1:] for m in modes} == {("disabled", True)}
        assert "terminal_evidence" not in done["result"]["combined_test"]
        assert tc.screenshot_mode() == "terminal"  # only the batch thread is switched off

    def test_unknown_batch_is_404(self, api):
        assert api.client.get("/api/v1/sandbox/batches/nope").status_code == 404


def dead_pid():
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    return process.pid


def record_running(world, run_id, owner):
    history.record(world.request("fix-a"), {
        "run_id": run_id, "schema_version": "sandbox-batch-v1", "status": "RUNNING", "snapshot_hash": "x",
        "spec_set_hash": "h", "spec_hashes": {}, "fixes": [], "owner": owner,
        "progress": {"status": "RUNNING", "done": 4, "total": 12, "phase": "individual", "current_fix": "fix-b",
                     "step": "individual", "step_text": "Testing fix 5 of 10 on its own: b (low risk)…",
                     "elapsed_seconds": 61.0, "estimate_seconds": 90, "steps": [{"at": "t", "text": "earlier"}]}})


class TestInterrupted:
    def test_a_batch_running_when_the_process_died_is_marked_interrupted(self, api):
        record_running(api.world, "batch-dead", {"pid": dead_pid(), "token": "previous-process"})
        # Same PID, other token: the restarted service got the PID of the one that died.
        record_running(api.world, "batch-same-pid", {"pid": os.getpid(), "token": "previous-process"})
        # A batch another live service process is running (shared history folder) is left alone.
        record_running(api.world, "batch-other-live", {"pid": os.getppid(), "token": "other-process"})
        view = api.client.get("/api/v1/sandbox/batches/batch-dead").json()
        assert view["status"] == "INTERRUPTED" and view["result"] is None
        assert "service stopped" in view["reason"] and view["step_text"] == view["reason"]
        assert (view["done"], view["total"], view["current_fix"], view["estimate_seconds"]) == (4, 12, None, 0)
        assert view["steps"] == [{"at": "t", "text": "earlier"}]
        listed = {r["run_id"]: r["status"] for r in api.client.get("/api/v1/history").json()["runs"]}
        assert listed == {"batch-dead": "INTERRUPTED", "batch-same-pid": "INTERRUPTED",
                          "batch-other-live": "RUNNING"}
        assert history.get("batch-dead")["result"]["reason"] == batch_jobs.INTERRUPTED_REASON
        # An interrupted batch does not block a new one.
        assert api.client.post("/api/v1/sandbox/batches", json=body("fix-a")).status_code == 202

    def test_a_batch_this_process_is_running_is_not_interrupted(self, api):
        api.world.gate = threading.Event()
        accepted = api.client.post("/api/v1/sandbox/batches", json=body("fix-a")).json()
        try:
            assert batch_jobs.reconcile() == []
            assert history.get(accepted["batch_id"])["result"]["status"] == "RUNNING"
            assert history.get(accepted["batch_id"])["result"]["owner"] == batch_jobs.owner()
        finally:
            api.world.gate.set()
        assert wait_for(api.client, accepted["batch_id"])["status"] == "VERIFIED"

    def test_reassessment_helper_accepts_a_partial_batch(self):
        steps = [{"after": {"marker": 1}}]
        result = {"status": "PARTIAL", "combined_test": {"status": "VERIFIED", "steps": steps}}
        assert history._applied_snapshot(result) == {"marker": 1}
        assert history._applied_snapshot({**result, "status": "FAILED"}) is None


# ---------------------------------------------------------------------------
# Restart rounds: one restart, unless a restart fix builds on another's setting
# ---------------------------------------------------------------------------

def restart_result(fid, *params, kind="catalog_setting"):
    unit = ({"fix_id": fid, "changes": [{"param": p} for p in params]} if kind == "catalog_setting"
            else {"fix_id": fid, "apply": {"param": params[0]}})
    return {"kind": kind, "fix_unit": unit, "risk_review": {"fix_id": fid, "requires": "restart"}}


class TestRestartRounds:
    def test_independent_restart_fixes_share_one_round(self):
        group = [restart_result("fix-listen", "listen_addresses", kind="setting"),
                 restart_result("fix-collector", "logging_collector", kind="setting"),
                 restart_result("fix-pgaudit", "shared_preload_libraries", "pgaudit.log")]
        assert batch_module.restart_rounds(group) == [group]

    def test_a_chained_preload_fix_waits_for_the_restart_of_the_first(self):
        # 3.2 and 5.6 both append to shared_preload_libraries: the second is derived from the
        # sandbox's own state after the first, which exists only after the first restart.
        collector = restart_result("fix-collector", "logging_collector", kind="setting")
        password = restart_result("fix-passwordcheck", "shared_preload_libraries")
        pgaudit = restart_result("fix-pgaudit", "shared_preload_libraries", "pgaudit.log")
        assert batch_module.restart_rounds([collector, password, pgaudit]) == [[collector, password], [pgaudit]]
        reload_fix = {"kind": "setting", "fix_unit": {"fix_id": "fix-a", "apply": {"param": "a"}},
                      "risk_review": {"fix_id": "fix-a", "requires": "reload"}}
        assert batch_module.execution_order([collector, password, reload_fix, pgaudit]) == [
            reload_fix, collector, password, pgaudit]

    def test_bundle_guard_states_compose_within_a_round_only(self):
        def snap(**values):
            return {"baseline": {"settings": [{"name": n, "setting": v} for n, v in values.items()],
                                 "file_settings": []}}
        before1, after1 = snap(a="0", b="0", s="x"), snap(a="1", b="1", s="x")
        after2 = snap(a="1", b="1", s="x,y")
        results = [restart_result("fix-a", "a", kind="setting"), restart_result("fix-b", "b", kind="setting"),
                   restart_result("fix-s", "s")]
        steps = [{"phase": 2, "restart_round": 1, "before": before1, "after": after1},
                 {"phase": 2, "restart_round": 1, "before": before1, "after": after1},
                 {"phase": 2, "restart_round": 2, "before": after1, "after": after2}]
        values = [[{r["name"]: r["setting"] for r in s["baseline"]["settings"]} for s in pair]
                  for pair in batch_module._bundle_states(results, steps)]
        assert values == [[{"a": "0", "b": "0", "s": "x"}, {"a": "1", "b": "0", "s": "x"}],
                          [{"a": "1", "b": "0", "s": "x"}, {"a": "1", "b": "1", "s": "x"}],
                          [{"a": "1", "b": "1", "s": "x"}, {"a": "1", "b": "1", "s": "x,y"}]]


# ---------------------------------------------------------------------------
# One command for the whole package (E2E Gate 1, decision 2)
# ---------------------------------------------------------------------------

class TestOnePackageCommand:
    @staticmethod
    def top_level(data):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return {name: archive.read(name) for name in archive.namelist() if "/" not in name}

    def test_the_package_has_the_runner_its_order_and_a_manifest_covering_it(self, faked):
        from services.sandbox_poc import package_assets
        world = faked(ten_fixes())
        output, data = run(world)
        files = self.top_level(data)
        for name in package_assets.REQUIRED_FILES:
            assert name in files, name
        package = json.loads(files["package.json"])
        assert package["run_id"] == output["run_id"] and package["database"] == "appdb"
        assert [f["fix_id"] for f in package["fixes"]] == output["recommended_order"]
        assert all(f["folder"] == f["fix_id"] for f in package["fixes"])
        manifest = json.loads(files["manifest.json"])["files"]
        for name in package_assets.REQUIRED_FILES:
            assert manifest[name] == hashlib.sha256(files[name]).hexdigest(), name
        assert set(manifest) <= package_assets.TOP_LEVEL_FILES and "README.txt" not in manifest
        assert "ONE COMMAND FOR THE WHOLE PACKAGE" in files["README.txt"].decode()
        assert b"package_runner.py" in files["harden.sh"]

    def test_a_partial_package_lists_only_the_fixes_proven_together(self, faked):
        world = faked(ten_fixes())
        world.verify_fails.add(("*", "fix-s03"))
        world.individual["fix-s03"] = "FAILED"
        output, data = run(world)
        package = json.loads(self.top_level(data)["package.json"])
        passed = [f["fix_id"] for f in output["fixes"] if f["status"] == "PASSED"]
        assert output["status"] == "PARTIAL" and "fix-s03" not in [f["fix_id"] for f in package["fixes"]]
        assert sorted(f["fix_id"] for f in package["fixes"]) == sorted(passed)


# ---------------------------------------------------------------------------
# Client-impact warnings travel into the package (E2E Gate 1, decision 3)
# ---------------------------------------------------------------------------

class TestClientActionsInThePackage:
    def warned_world(self, faked):
        from services.sandbox_poc import client_impact
        world = World(**{"fix-a": ("low", "reload"), "fix-tls": ("high", "reload")})
        plain = world.review
        warning = client_impact.tls_protocol(
            {"baseline": {"connections": [{"backend_type": "client backend", "visible": True,
                                           "client_addr_class": "private", "connection_count": 3,
                                           "usename": "billing_svc", "datname": "appdb", "ssl": True,
                                           "tls_version": "TLSv1.1", "tls_cipher": "x"}]}}, "TLSv1.2")
        world.review = lambda fid: {**plain(fid), **({"client_impact": warning} if fid == "fix-tls" else {})}
        return faked(world)

    def test_flag_actions_file_readme_and_report_carry_the_warning(self, faked):
        world = self.warned_world(faked)
        output, data = run(world)
        files = TestOnePackageCommand.top_level(data)
        package = {f["fix_id"]: f for f in json.loads(files["package.json"])["fixes"]}
        assert package["fix-tls"]["client_impact"] is True and package["fix-a"]["client_impact"] is False
        actions = files["CLIENT-ACTIONS.txt"].decode()
        assert "[fix-tls]" in actions and "3 connections right now would be affected" in actions
        assert "--ack-client-impact" in actions and "[fix-a]" not in actions
        assert files["README.txt"].decode().startswith("!!! CLIENT ACTION REQUIRED for 1 fix(es)")
        report = files["report.html"].decode()
        assert report.index("Client action required") < report.index("<ol>")
        manifest = json.loads(files["manifest.json"])["files"]
        assert manifest["CLIENT-ACTIONS.txt"] == hashlib.sha256(files["CLIENT-ACTIONS.txt"]).hexdigest()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            assert json.loads(z.read("fix-tls/fix.json"))["client_impact"] is True

    def test_no_warning_means_no_actions_file(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload")}))
        output, data = run(world)
        files = TestOnePackageCommand.top_level(data)
        assert "CLIENT-ACTIONS.txt" not in files
        assert all(f["client_impact"] is False for f in json.loads(files["package.json"])["fixes"])



# ---------------------------------------------------------------------------
# PostgreSQL does not start after the joint restart (fix of 12 Nov 2026)
# ---------------------------------------------------------------------------

class TestRestartThatDoesNotComeBack:
    """Found in the demo: log_directory + logging_collector could not start on the sandbox's
    read-only file system, and the run then failed all 10 fixes because the undo could not
    connect. Now the restart round is left out and the rest are retried."""

    def world(self, faked):
        return faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("medium", "reload"),
                              "fix-collector": ("medium", "restart"), "fix-pgaudit": ("medium", "restart")}))

    def test_the_restart_round_is_left_out_and_the_rest_are_packaged(self, faked):
        world = self.world(faked)
        world.start_fails = {1}
        output, data = run(world)
        assert output["status"] == "PARTIAL", output
        st = statuses(output)
        assert st["fix-a"] == st["fix-b"] == ("PASSED", "combined")
        assert st["fix-collector"] == st["fix-pgaudit"] == ("FAILED", "combined")
        by_id = {f["fix_id"]: f for f in output["fixes"]}
        # 12 Nov: each restart fix of the round got its own test first; both pass alone.
        assert world.ran == ["fix-collector", "fix-pgaudit"]
        assert "cannot be told apart" in by_id["fix-collector"]["reason"]
        assert "PostgreSQL failed to start after restart" in by_id["fix-pgaudit"]["reason"]
        assert folders(data) == ["fix-a", "fix-b"]
        first, second = output["combined_attempts"][0], output["combined_test"]
        assert first["start_failed"] is True and first["failed_fix_ids"] == ["fix-collector", "fix-pgaudit"]
        assert "rollback_error" not in first and first["rollback"] == [] and "discarded" in first["rollback_skipped"]
        assert first["hard_failure"] is False and first["cleanup"]["verified"] is True
        assert second["status"] == "VERIFIED" and len(second["rollback"]) == 2  # undo proven in the retry
        assert all(r.closed for r in world.runtimes) and len(world.runtimes) == 2
        assert any("discarding this copy" in t for t in texts(world))

    def test_a_copy_that_cannot_be_removed_is_still_a_hard_failure(self, faked):
        world = self.world(faked)
        world.start_fails, world.cleanup_fails = {1}, {1}
        output, data = run(world)
        assert output["status"] == "CLEANUP_FAILED" and data is None
        assert len(world.runtimes) == 1  # never retried

    def test_an_undo_failure_elsewhere_stays_a_hard_failure(self, faked):
        world = self.world(faked)
        world.rollback_stuck = {(1, "fix-a")}
        output, data = run(world)
        assert output["status"] == "FAILED" and data is None
        assert "rollback_error" in output["combined_test"] and len(world.runtimes) == 1

    def test_a_restart_that_fails_during_the_undo_stays_a_hard_failure(self, faked):
        # Security review note (12 Nov): only the apply restart is softened; the undo's
        # restart failing means the undo is unproven, so nothing is packaged or retried.
        world = self.world(faked)
        world.start_fail_at = {(1, 2)}  # the apply restart works; the undo's restart does not
        output, data = run(world)
        assert output["status"] == "FAILED" and data is None
        assert "rollback_error" in output["combined_test"] and output["combined_test"]["hard_failure"] is True
        assert len(world.runtimes) == 1


# ---------------------------------------------------------------------------
# Combined first, single tests only when needed (Melvin's ruling of 12 Nov 2026)
# ---------------------------------------------------------------------------

def package_configs(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name.split("/")[0]: json.loads(archive.read(name)) for name in archive.namelist()
                if name.endswith("/fix.json")}


class TestCombinedFirst:
    def test_a_passing_run_runs_no_single_test_and_one_sandbox(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-collector": ("high", "restart"),
                               "fix-truncate": ("high", "reload", ["fix-collector"], "fix-collector")}))
        output, data = run(world)
        assert output["status"] == "VERIFIED", output
        assert world.ran == [] and output["individual_runs"] == [] and len(world.runtimes) == 1
        assert sorted(world.prepared) == sorted(world.fixes)
        assert [a["status"] for a in output["combined_attempts"]] == ["VERIFIED"]
        assert not any(e["kind"].startswith("individual") for e in world.events)
        # Every folder comes from the one combined test, none from a single test.
        configs = package_configs(data)
        assert sorted(configs) == sorted(world.fixes)
        assert all(c["run_id"] == "combined-1" and c["combined_run_id"] == output["run_id"]
                   and c["single_test"] is None for c in configs.values())

    @pytest.mark.parametrize("alone,stage", [("VERIFIED", "combined"), ("FAILED", "individual")])
    def test_a_phase_1_failure_gets_a_single_test_for_that_fix_only(self, faked, alone, stage):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload"),
                               "fix-c": ("medium", "reload"), "fix-r": ("high", "restart")}))
        world.verify_fails.add((1, "fix-b"))
        world.individual["fix-b"] = alone
        output, data = run(world)
        assert output["status"] == "PARTIAL"
        assert world.ran == ["fix-b"]
        assert output["individual_runs"] == [{"run_id": "run-fix-b", "fix_id": "fix-b", "status": alone}]
        got = statuses(output)
        assert got["fix-b"] == ("FAILED", stage)
        assert got["fix-a"] == got["fix-c"] == got["fix-r"] == ("PASSED", "combined")
        reason = output["fixes"][1]["reason"]
        if stage == "individual":
            assert reason == "health check failed"
        else:
            assert reason.startswith("It passes its own test, but not together with the other fixes")
            assert "functional gate failed" in reason
        assert len(world.runtimes) == 2 and "APPLY fix-b" not in world.runtimes[1].log
        assert folders(data) == ["fix-a", "fix-c", "fix-r"]
        # The single test ran after the failed combined attempt and before the retry.
        kinds = [e["kind"] for e in world.events]
        starts = [i for i, k in enumerate(kinds) if k == "combined_start"]
        assert starts[0] < kinds.index("combined_done") < kinds.index("individual_start") \
            < kinds.index("individual_done") < starts[1]

    def test_a_restart_that_does_not_come_back_leaves_out_only_the_culprit(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("medium", "reload"),
                               "fix-collector": ("medium", "restart"), "fix-pgaudit": ("medium", "restart")}))
        world.start_fails = {1}
        world.individual["fix-pgaudit"] = "FAILED"
        output, data = run(world)
        assert output["status"] == "PARTIAL", output
        assert world.ran == ["fix-collector", "fix-pgaudit"]  # each restart fix of that round, one by one
        got = statuses(output)
        assert got["fix-pgaudit"] == ("FAILED", "individual") and output["fixes"][3]["reason"] == "health check failed"
        assert got["fix-collector"] == got["fix-a"] == got["fix-b"] == ("PASSED", "combined")
        first, final = output["combined_attempts"]
        assert first["start_failed"] is True and first["failed_fix_ids"] == ["fix-collector", "fix-pgaudit"]
        assert final["status"] == "VERIFIED" and final["phases"]["2"] == ["fix-collector"] and final["restarts"] == 1
        assert len(world.runtimes) == 2 and all(r.closed for r in world.runtimes)
        assert folders(data) == ["fix-a", "fix-b", "fix-collector"]
        # The packaged restart fix also ran on its own; its folder reports that test too.
        configs = package_configs(data)
        assert configs["fix-collector"]["single_test"] == "run-fix-collector"
        assert configs["fix-a"]["single_test"] is None
        lines = texts(world)
        assert ("PostgreSQL did not start after the restart for fix-collector, fix-pgaudit; testing each of these "
                "restart fixes on its own to find the cause…") in lines
        assert "Testing restart fix 1 of 2 on its own: collector (medium risk)…" in lines
        assert "Testing restart fix 2 of 2 on its own: pgaudit (medium risk)…" in lines

    def test_restart_fixes_that_all_fail_alone_are_all_left_out(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-collector": ("medium", "restart"),
                               "fix-pgaudit": ("medium", "restart")}))
        world.start_fails = {1}
        world.individual.update({"fix-collector": "FAILED", "fix-pgaudit": "FAILED"})
        output, data = run(world)
        assert output["status"] == "PARTIAL"
        got = statuses(output)
        assert got["fix-collector"] == got["fix-pgaudit"] == ("FAILED", "individual")
        assert "cannot be told apart" not in json.dumps(output["fixes"])
        assert folders(data) == ["fix-a"] and world.runtimes[1].restarts == 0

    def test_a_single_restart_fix_that_passes_alone_is_left_out_as_combined(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-collector": ("medium", "restart")}))
        world.start_fails = {1}
        output, data = run(world)
        assert output["status"] == "PARTIAL" and world.ran == ["fix-collector"]
        assert statuses(output)["fix-collector"] == ("FAILED", "combined")
        assert "PostgreSQL failed to start after restart" in output["fixes"][1]["reason"]
        assert folders(data) == ["fix-a"]

    def test_a_preparation_failure_never_reaches_a_sandbox(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload"),
                               "fix-r": ("high", "restart")}))
        world.prepare_errors["fix-b"] = ContractError("Approved template is outside the supported setting action")
        output, data = run(world)
        assert output["status"] == "PARTIAL"
        assert output["fixes"][1] == {"fix_id": "fix-b", "status": "FAILED", "stage": "preparation",
                                      "reason": "Approved template is outside the supported setting action"}
        assert world.ran == [] and len(world.runtimes) == 1
        assert not any("fix-b" in line for line in world.runtimes[0].log)
        assert folders(data) == ["fix-a", "fix-r"] and output["recommended_order"] == ["fix-a", "fix-r"]
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            readme = archive.read("README.txt").decode()
        assert "fix-b: FAILED (preparation): Approved template is outside" in readme

    def test_a_prepared_fix_that_differs_from_the_request_is_refused(self, faked):
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-b": ("low", "reload")}))
        original = world.prepare

        def swapped(request):
            item = original(request)
            if item["fix_unit"]["fix_id"] == "fix-b":
                item["fix_unit"]["spec_id"] = "c:fix-a"
            return item
        world.prepare = swapped
        output, _ = run(world)
        assert statuses(output)["fix-b"] == ("FAILED", "preparation")
        assert output["fixes"][1]["reason"] == "The prepared fix differs from the selected fix"

    def test_a_restart_fix_already_tested_alone_is_not_tested_again(self, faked):
        # Round 1 fails to start; pgaudit fails alone and is left out. The retry's restart
        # fails too: collector passed alone already, so it is not tested again, only left out.
        world = faked(World(**{"fix-a": ("low", "reload"), "fix-collector": ("medium", "restart"),
                               "fix-pgaudit": ("medium", "restart")}))
        world.start_fails = {1, 2}
        world.individual["fix-pgaudit"] = "FAILED"
        output, data = run(world)
        assert world.ran == ["fix-collector", "fix-pgaudit"]
        got = statuses(output)
        assert got["fix-pgaudit"] == ("FAILED", "individual") and got["fix-collector"] == ("FAILED", "combined")
        assert output["status"] == "PARTIAL" and folders(data) == ["fix-a"] and len(world.runtimes) == 3

