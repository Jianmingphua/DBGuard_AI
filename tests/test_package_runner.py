"""The combined package's one-command runner (E2E Gate 1, decision 2). Fakes only: no
database, no VHS. Each fix's own runner.py is replaced by a scripted fake; the real
subprocess path is checked with a tiny stand-in runner.py."""
import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from services.sandbox_poc import package_assets
from services.sandbox_poc.bundle_assets import package_runner as pr
from services.sandbox_poc.bundle_assets import terminal_evidence as te
from services.sandbox_poc.shared import ContractError

RUN_ID = "0f0e0d0c-0b0a-4908-8706-050403020100"
DSN = "host=db.internal.example port=6543 user=dba_admin password=s3cr3t-Pw dbname=appdb"
PNG = b"\x89PNG\r\n\x1a\n" + b"fake-picture"
ASSETS = Path(pr.__file__).parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fix(fix_id, requires="reload", client_impact=False, setting=None):
    return {"fix_id": fix_id, "folder": fix_id, "requires": requires, "client_impact": client_impact,
            "setting": setting or fix_id[len("fix-"):]}


THREE = [fix("fix-log_connections"), fix("fix-log_disconnections"), fix("fix-logging_collector", "restart")]


def make_package(root, fixes, run_id=RUN_ID, runner_source="# stand-in\n"):
    root.mkdir(parents=True, exist_ok=True)
    for item in fixes:
        folder = root / item["folder"]
        folder.mkdir()
        config = {"fix_id": item["fix_id"], "database": "appdb", "requires": item["requires"],
                  "setting": item["setting"], "target_id": "target-01", "run_id": "single-" + item["fix_id"],
                  "combined_run_id": run_id, "demo_fixture_approval": False}
        members = {"fix.json": json.dumps(config).encode(), "runner.py": runner_source.encode()}
        for name, data in members.items():
            (folder / name).write_bytes(data)
        (folder / "manifest.json").write_text(json.dumps(
            {"schema_version": "review-bundle-v1", "files": {n: sha(d) for n, d in members.items()}}))
    files = dict(package_assets.package_files())
    files["package.json"] = package_assets.package_json(run_id, "appdb", fixes, target_id="target-01",
                                                        system_identifier="7300000000000000001")
    files["combined-evidence.json"] = b"{}"
    files["manifest.json"] = json.dumps({"schema_version": "review-bundle-v1", "run_id": run_id,
                                         "files": package_assets.manifest_entries(files)}).encode()
    for name, data in files.items():
        (root / name).write_bytes(data)
    return root


class FakeRunner:
    """Scripted stand-in for each <folder>/runner.py: {(action, fix_id): outcome}."""

    def __init__(self, log, restart=(), script=None):
        self.log, self.restart, self.script, self.calls = log, set(restart), dict(script or {}), []

    def __call__(self, base, fix, action, *, dsn, allow_demo=False, ack=False, evidence_dir=None):
        self.calls.append({"action": action, "fix_id": fix["fix_id"], "ack": ack, "allow_demo": allow_demo,
                           "dsn": dsn, "evidence_dir": str(evidence_dir)})
        self.log.append((action, fix["fix_id"]))
        outcome = self.script.get((action, fix["fix_id"]))
        if outcome is not None:
            return outcome
        if action == "status":
            return {"ok": True, "result": {"matches_prior": True, "matches_applied": False}, "message": ""}
        if action in ("apply", "rollback") and fix["fix_id"] in self.restart:
            return {"ok": True, "message": "", "result": {"action": action, "verified": False,
                                                          "status": "RESTART_REQUIRED", "fix_id": fix["fix_id"]}}
        return {"ok": True, "result": {"action": action, "verified": True, "fix_id": fix["fix_id"]}, "message": ""}

    def actions(self, action):
        return [c["fix_id"] for c in self.calls if c["action"] == action]


FAIL = {"ok": False, "result": None, "message": "Configuration drift detected; no SQL executed. Recollect and reassess."}


@pytest.fixture
def rig(tmp_path, monkeypatch, capsys):
    """A package folder, a fake per-fix runner and a fake capture that logs when it ran."""
    log = []

    def fake_capture(stage, *, dsn, run_id, target_id, targets, mode="terminal", connect=None):
        log.append(("picture", stage))
        return {"stage": stage, "stage_label": te.STAGES[stage], "run_id": run_id, "target_id": target_id,
                "status": "CAPTURED", "mode": mode, "png": PNG, "sha256": sha(PNG), "reason": None,
                "typed_command": None, "captured_at": "2026-11-11T00:00:00Z",
                "raw_output": [{"title": "t", "query": "SELECT 1;", "columns": ["x"], "rows": [["1"]], "output": "x"}],
                "raw_output_sha256": "a" * 64, "database": "appdb", "system_identifier": "7300000000000000001",
                "tools": {}, "targets": targets}

    monkeypatch.setattr(te, "capture", fake_capture)
    monkeypatch.setenv("DBGUARD_DSN", DSN)

    class Rig:
        def __init__(self):
            self.log, self.base, self.runner = log, None, None

        def package(self, fixes=THREE, **kwargs):
            self.base = make_package(tmp_path / "package", fixes)
            self.runner = FakeRunner(log, **kwargs)
            return self

        def run(self, *argv):
            code = pr.main(list(argv), base=self.base, runner=self.runner)
            captured = capsys.readouterr()
            self.out, self.err = captured.out, captured.err
            return code

        def state(self):
            return json.loads((self.base / pr.STATE_FILE).read_text())

    return Rig()


APPLY = ("apply-all", "--ack-prerequisites", "--ack-client-impact")


# ---------------------------------------------------------------------------
# apply-all
# ---------------------------------------------------------------------------

def test_apply_all_takes_the_before_picture_then_applies_in_package_order(rig):
    rig.package(restart={"fix-logging_collector"})
    code = rig.run(*APPLY)
    assert rig.log == [("picture", "before"), ("apply", "fix-log_connections"),
                       ("apply", "fix-log_disconnections"), ("apply", "fix-logging_collector")]
    assert all(c["ack"] is True for c in rig.runner.calls)
    assert code == pr.EXIT_RESTART
    state = rig.state()
    assert [e["fix_id"] for e in state["applied"]] == [f["fix_id"] for f in THREE]
    assert [e["status"] for e in state["applied"]] == [pr.VERIFIED, pr.VERIFIED, pr.RESTART_PENDING]
    assert all(e["applied_at"].endswith("Z") for e in state["applied"])
    assert state["run_id"] == RUN_ID
    assert stat.S_IMODE((rig.base / pr.STATE_FILE).stat().st_mode) == 0o600


def test_restart_fixes_end_with_exactly_the_restart_line_and_nothing_is_restarted(rig, monkeypatch):
    started = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: started.append(a) or pytest.fail("no process may start"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: started.append(a) or pytest.fail("no process may start"))
    rig.package(restart={"fix-logging_collector"})
    assert rig.run(*APPLY) == pr.EXIT_RESTART
    assert rig.out.rstrip("\n").splitlines()[-1] == "RESTART POSTGRESQL NOW, then run: sh harden.sh verify-all"
    assert pr.RESTART_LINE == "RESTART POSTGRESQL NOW, then run: sh harden.sh verify-all"
    assert started == []
    assert "fix-logging_collector" in rig.out


def test_apply_all_without_restart_fixes_finishes_with_exit_0(rig):
    rig.package(THREE[:2])
    assert rig.run(*APPLY) == pr.EXIT_OK
    assert pr.RESTART_LINE not in rig.out
    assert "sh harden.sh verify-all" in rig.out


def test_apply_all_stops_at_the_first_failure_and_lists_what_was_applied(rig):
    rig.package(script={("apply", "fix-log_disconnections"): FAIL})
    assert rig.run(*APPLY) == pr.EXIT_FAILED
    assert rig.runner.actions("apply") == ["fix-log_connections", "fix-log_disconnections"]  # third never run
    state = rig.state()
    assert [e["fix_id"] for e in state["applied"]] == ["fix-log_connections"]
    assert state["failed"]["fix_id"] == "fix-log_disconnections"
    assert "STOPPED at fix-log_disconnections: Configuration drift detected" in rig.out
    assert "Already applied by this package, in order: fix-log_connections" in rig.out
    assert "Not run: fix-log_disconnections, fix-logging_collector" in rig.out
    assert pr.RESTART_LINE not in rig.out


def test_a_runner_that_reports_neither_verified_nor_restart_is_a_failure(rig):
    rig.package(script={("apply", "fix-log_connections"): {"ok": True, "message": "",
                                                           "result": {"action": "apply", "verified": False}}})
    assert rig.run(*APPLY) == pr.EXIT_FAILED
    assert rig.state()["applied"] == []
    assert rig.runner.actions("apply") == ["fix-log_connections"]


def test_apply_all_again_resumes_after_the_recorded_fixes_and_keeps_the_first_before_picture(rig):
    rig.package(script={("apply", "fix-log_disconnections"): FAIL})
    assert rig.run(*APPLY) == pr.EXIT_FAILED
    rig.runner.script.clear()
    del rig.log[:]
    assert rig.run(*APPLY) == pr.EXIT_OK
    assert rig.log == [("apply", "fix-log_disconnections"), ("apply", "fix-logging_collector")]  # no new picture
    assert [e["fix_id"] for e in rig.state()["applied"]] == [f["fix_id"] for f in THREE]
    assert rig.state()["failed"] is None


@pytest.mark.parametrize("argv", [("apply-all",), ("apply-all", "--ack-client-impact")])
def test_apply_all_refuses_without_ack_prerequisites(rig, argv):
    rig.package()
    assert rig.run(*argv) == pr.EXIT_REFUSED
    assert rig.log == [] and not (rig.base / pr.STATE_FILE).exists()
    assert "--ack-prerequisites" in rig.err


def test_apply_all_refuses_without_ack_client_impact_when_a_fix_has_client_impact(rig):
    rig.package([fix("fix-log_connections"), fix("fix-ssl_min_protocol_version", client_impact=True)])
    assert rig.run("apply-all", "--ack-prerequisites") == pr.EXIT_REFUSED
    assert rig.log == []
    assert "fix-ssl_min_protocol_version" in rig.err and "--ack-client-impact" in rig.err
    assert "CLIENT-ACTIONS.txt" in rig.err
    assert rig.run(*APPLY) == pr.EXIT_OK


def test_ack_client_impact_is_not_needed_when_no_fix_has_client_impact(rig):
    rig.package(THREE[:2])
    assert rig.run("apply-all", "--ack-prerequisites") == pr.EXIT_OK


def test_allow_demo_is_passed_to_every_fix_runner(rig):
    rig.package(THREE[:2])
    rig.run(*APPLY, "--allow-demo")
    assert all(c["allow_demo"] is True for c in rig.runner.calls)
    rig.run("status")
    assert [c["allow_demo"] for c in rig.runner.calls[2:]] == [False, False]


# ---------------------------------------------------------------------------
# verify-all, rollback-all, status
# ---------------------------------------------------------------------------

def test_verify_all_verifies_the_restart_fixes_then_takes_the_after_picture(rig):
    rig.package(restart={"fix-logging_collector"})
    rig.run(*APPLY)
    del rig.log[:]
    assert rig.run("verify-all") == pr.EXIT_OK
    # Security review finding 7: every applied fix is verified again (fresh connection),
    # not only the restart fixes, so "verified" never relies on a check made before the restart.
    assert rig.log == [("verify", "fix-log_connections"), ("verify", "fix-log_disconnections"),
                       ("verify", "fix-logging_collector"), ("picture", "after")]
    assert [e["status"] for e in rig.state()["applied"]] == [pr.VERIFIED] * 3
    assert "All 3 fix(es) verified." in rig.out
    assert "fix-log_connections: verified now in a fresh connection" in rig.out


def test_verify_all_failure_stops_without_an_after_picture(rig):
    rig.package(restart={"fix-logging_collector"}, script={("verify", "fix-logging_collector"): {
        "ok": False, "result": None, "message": "Verification failed: scoped values or configuration sources differ"}})
    rig.run(*APPLY)
    del rig.log[:]
    assert rig.run("verify-all") == pr.EXIT_FAILED
    assert ("picture", "after") not in rig.log
    assert rig.state()["applied"][-1]["status"] == pr.RESTART_PENDING
    assert "restart it and run verify-all again" in rig.out


def test_verify_all_refuses_when_nothing_was_applied(rig):
    rig.package()
    assert rig.run("verify-all") == pr.EXIT_REFUSED
    assert rig.log == []


def test_rollback_all_only_touches_recorded_fixes_in_reverse_order(rig):
    rig.package(script={("apply", "fix-logging_collector"): FAIL})
    assert rig.run(*APPLY) == pr.EXIT_FAILED  # only the first two are recorded
    del rig.log[:]
    assert rig.run("rollback-all") == pr.EXIT_OK
    assert rig.log == [("rollback", "fix-log_disconnections"), ("rollback", "fix-log_connections"),
                       ("picture", "rollback")]
    state = rig.state()
    assert state["applied"] == []
    assert [e["fix_id"] for e in state["rolled_back"]] == ["fix-log_disconnections", "fix-log_connections"]
    assert "fix-logging_collector stopped part-way" in rig.out  # the failed fix is named, never rolled back


def test_rollback_all_refuses_when_nothing_was_applied(rig):
    rig.package()
    assert rig.run("rollback-all") == pr.EXIT_REFUSED
    assert rig.log == []


def test_rollback_all_stops_at_a_failure_and_keeps_the_rest_recorded(rig):
    rig.package(THREE[:2], script={("rollback", "fix-log_disconnections"): FAIL})
    rig.run(*APPLY)
    del rig.log[:]
    assert rig.run("rollback-all") == pr.EXIT_FAILED
    assert rig.log == [("rollback", "fix-log_disconnections")]
    assert [e["fix_id"] for e in rig.state()["applied"]] == ["fix-log_connections", "fix-log_disconnections"]


def test_a_restart_required_rollback_stops_prints_the_line_and_is_finished_by_verify_all_rollback(rig):
    rig.package(restart={"fix-logging_collector"})
    rig.run(*APPLY)
    rig.run("verify-all")
    del rig.log[:]
    assert rig.run("rollback-all") == pr.EXIT_RESTART
    assert rig.log == [("rollback", "fix-logging_collector")]  # one restart-required rollback at a time
    assert rig.out.rstrip("\n").splitlines()[-1] == "RESTART POSTGRESQL NOW, then run: sh harden.sh verify-all --rollback"
    assert rig.state()["applied"][-1]["status"] == pr.ROLLBACK_PENDING
    for blocked in (("rollback-all",), ("verify-all",), APPLY):
        assert rig.run(*blocked) == pr.EXIT_REFUSED
        assert "verify-all --rollback" in rig.err
    del rig.log[:]
    assert rig.run("verify-all", "--rollback") == pr.EXIT_OK
    assert rig.log == [("verify-rollback", "fix-logging_collector")]  # no picture yet: two fixes remain
    assert "Next: sh harden.sh rollback-all" in rig.out
    del rig.log[:]
    assert rig.run("rollback-all") == pr.EXIT_OK
    assert rig.log == [("rollback", "fix-log_disconnections"), ("rollback", "fix-log_connections"),
                       ("picture", "rollback")]
    assert rig.state()["applied"] == []


def test_verify_all_rollback_takes_the_picture_when_the_last_fix_is_undone(rig):
    rig.package([THREE[2]], restart={"fix-logging_collector"})
    rig.run(*APPLY)
    rig.run("rollback-all")
    del rig.log[:]
    assert rig.run("verify-all", "--rollback") == pr.EXIT_OK
    assert rig.log == [("verify-rollback", "fix-logging_collector"), ("picture", "rollback")]


def test_verify_all_rollback_refuses_when_no_rollback_is_waiting(rig):
    rig.package()
    assert rig.run("verify-all", "--rollback") == pr.EXIT_REFUSED


def test_status_reports_applied_not_applied_and_drift(rig):
    rig.package(script={
        ("status", "fix-log_connections"): {"ok": True, "message": "", "result": {"matches_prior": False, "matches_applied": True}},
        ("status", "fix-logging_collector"): {"ok": True, "message": "", "result": {"matches_prior": False, "matches_applied": False}}})
    assert rig.run("status") == pr.EXIT_OK
    lines = rig.out.splitlines()
    assert lines[1] == "1. fix-log_connections: applied"
    assert lines[2] == "2. fix-log_disconnections: not applied"
    # Fix of 16 Nov: a later fix's tested "before" assumes the fixes ahead of it are applied,
    # so on a target where they are not, it is "not applied yet", never a false drift.
    assert lines[3] == "3. fix-logging_collector: not applied yet (checked when the fixes before it are applied)"
    assert ("picture", "before") not in rig.log and not (rig.base / pr.STATE_FILE).exists()


def test_status_still_reports_real_drift_on_the_next_fix_due(rig):
    rig.package(script={
        ("status", "fix-log_connections"): {"ok": True, "message": "", "result": {"matches_prior": False, "matches_applied": False}}})
    assert rig.run("status") == pr.EXIT_OK
    assert rig.out.splitlines()[1].startswith("1. fix-log_connections: drift")


def test_status_exit_1_when_a_fix_cannot_be_checked(rig):
    rig.package(script={("status", "fix-log_connections"): FAIL})
    assert rig.run("status") == pr.EXIT_FAILED
    assert "1. fix-log_connections: unknown" in rig.out


# ---------------------------------------------------------------------------
# A picture problem never changes a result
# ---------------------------------------------------------------------------

def test_a_capture_crash_never_changes_the_apply_result(rig, monkeypatch):
    monkeypatch.setattr(te, "capture", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom " + DSN)))
    rig.package(THREE[:2])
    assert rig.run(*APPLY) == pr.EXIT_OK
    assert rig.runner.actions("apply") == ["fix-log_connections", "fix-log_disconnections"]
    assert "the result of this command is unchanged" in rig.out
    assert "boom" not in rig.out + rig.err
    assert rig.run("verify-all") == pr.EXIT_OK
    assert rig.run("rollback-all") == pr.EXIT_OK


def test_an_unavailable_picture_prints_its_reason_and_the_result_stands(rig, monkeypatch):
    def unavailable(stage, **kwargs):
        return {"stage": stage, "run_id": RUN_ID, "status": "UNAVAILABLE", "mode": "rendered",
                "reason": "Terminal capture UNAVAILABLE: VHS is not installed. Rendered capture also failed."}

    monkeypatch.setattr(te, "capture", unavailable)
    rig.package(THREE[:2])
    assert rig.run(*APPLY) == pr.EXIT_OK
    assert "Picture BEFORE: none. Terminal capture UNAVAILABLE: VHS is not installed." in rig.out
    event = json.loads((rig.base / "target-evidence" / "event-before.json").read_text())
    assert event["status"] == "UNAVAILABLE" and event["png_sha256"] is None
    assert event["step"]["result"] == "COMPLETED"
    assert not (rig.base / "target-evidence" / "before.png").exists()


def test_screenshot_mode_and_evidence_dir_reach_the_capture(rig, monkeypatch, tmp_path):
    seen = []
    real = te.capture
    monkeypatch.setattr(te, "capture", lambda stage, **k: seen.append(k["mode"]) or real(stage, **k))
    rig.package(THREE[:2])
    target = tmp_path / "elsewhere"
    assert rig.run(*APPLY, "--screenshots", "rendered", "--evidence-dir", str(target)) == pr.EXIT_OK
    assert seen == ["rendered"]
    assert (target / "before.png").read_bytes() == PNG
    assert (target / f"target-evidence-{RUN_ID}.zip").is_file()
    assert all(c["evidence_dir"] == str(target) for c in rig.runner.calls)


def test_the_event_records_the_step_result(rig):
    rig.package(restart={"fix-logging_collector"})
    rig.run(*APPLY)
    event = json.loads((rig.base / "target-evidence" / "event-before.json").read_text())
    assert event["step"]["command"] == "apply-all" and event["step"]["result"] == "RESTART_REQUIRED"
    assert [f["result"] for f in event["step"]["fixes"]] == ["VERIFIED", "VERIFIED", "RESTART_REQUIRED"]
    rig.run("verify-all")
    after = json.loads((rig.base / "target-evidence" / "event-after.json").read_text())
    assert after["step"]["result"] == "VERIFIED"
    assert [f["result"] for f in after["step"]["fixes"]] == ["VERIFIED", "VERIFIED", "VERIFIED"]  # review finding 7: all re-verified


# ---------------------------------------------------------------------------
# The DSN is never printed
# ---------------------------------------------------------------------------

HOSTILE_DSN = ("host='evil-host;$(id)' port=6543 user='ro\"ot $(whoami)' "
               "password='p:a\\\\ss;`x`' dbname=appdb")


def test_missing_dsn_is_refused_before_anything_runs(rig, monkeypatch):
    monkeypatch.delenv("DBGUARD_DSN")
    rig.package()
    assert rig.run(*APPLY) == pr.EXIT_REFUSED
    assert rig.log == [] and "DBGUARD_DSN" in rig.err


@pytest.mark.parametrize("leak", ["evil-host;$(id)", 'ro"ot $(whoami)', "p:a\\ss;`x`", "6543", HOSTILE_DSN])
def test_a_runner_message_holding_a_connection_value_is_withheld(leak):
    message = pr.safe_message(f"could not connect to {leak}: refused", HOSTILE_DSN)
    assert message == pr.WITHHELD


def test_a_plain_runner_message_is_shown_and_odd_output_is_withheld():
    plain = "Configuration drift detected; no SQL executed. Recollect and reassess."
    assert pr.safe_message("noise\n" + plain + "\n", DSN) == plain
    assert pr.safe_message("café \x1b[31m", DSN) == pr.WITHHELD
    assert pr.safe_message("x" * 500, DSN) == pr.WITHHELD
    assert pr.safe_message(plain, "not a dsn ===") == pr.WITHHELD  # unparsable DSN: nothing can be checked
    assert pr.safe_message("", DSN) == "The fix runner gave no reason."


def test_no_connection_value_reaches_the_output_state_or_evidence(rig, monkeypatch):
    monkeypatch.setenv("DBGUARD_DSN", HOSTILE_DSN)
    rig.package(restart={"fix-logging_collector"})
    rig.run(*APPLY)
    text = rig.out + rig.err
    rig.run("status")
    text += rig.out + rig.err
    rig.run("verify-all")
    text += rig.out + rig.err
    assert "6543" not in text  # the port, in everything printed (file hashes are hex, so checked here only)
    for path in rig.base.rglob("*"):
        if path.is_file() and path.suffix in (".json", ".txt", ".sh"):
            text += path.read_text()
    for value in ("evil-host", "$(id)", "whoami", "ro\"ot", "p:a", "`x`"):
        assert value not in text


# ---------------------------------------------------------------------------
# The package is checked before anything runs
# ---------------------------------------------------------------------------

def tamper_fix_json(base):
    (base / "fix-log_connections" / "fix.json").write_text("{}")


def tamper_package_json(base):
    path = base / "package.json"
    path.write_text(path.read_text().replace('"client_impact": false', '"client_impact":  false'))


def tamper_runner_asset(base):
    (base / "terminal_evidence.py").write_text("print('changed')\n")


def tamper_fix_runner(base):
    (base / "fix-log_disconnections" / "runner.py").write_text("import os\n")


def drop_manifest(base):
    (base / "manifest.json").unlink()


def add_manifest_member(base):
    manifest = json.loads((base / "manifest.json").read_text())
    (base / "extra.py").write_text("x = 1\n")
    manifest["files"]["extra.py"] = sha(b"x = 1\n")
    (base / "manifest.json").write_text(json.dumps(manifest))


def uncover_required_file(base):
    manifest = json.loads((base / "manifest.json").read_text())
    del manifest["files"]["package_runner.py"]
    (base / "manifest.json").write_text(json.dumps(manifest))


@pytest.mark.parametrize("tamper", [tamper_fix_json, tamper_package_json, tamper_runner_asset, tamper_fix_runner,
                                    drop_manifest, add_manifest_member, uncover_required_file])
def test_a_changed_package_is_refused_before_anything_runs(rig, tamper):
    rig.package()
    tamper(rig.base)
    assert rig.run(*APPLY) == pr.EXIT_REFUSED
    assert rig.log == [] and not (rig.base / pr.STATE_FILE).exists()


def rewrite_package(base, change):
    package = json.loads((base / "package.json").read_text())
    change(package)
    data = json.dumps(package).encode()
    (base / "package.json").write_bytes(data)
    manifest = json.loads((base / "manifest.json").read_text())
    manifest["files"]["package.json"] = sha(data)
    (base / "manifest.json").write_text(json.dumps(manifest))


@pytest.mark.parametrize("change", [
    lambda p: p["fixes"][0].update(folder="../outside"),
    lambda p: p["fixes"][0].update(folder="fix-log_disconnections"),
    lambda p: p["fixes"][0].update(fix_id="fix-something_else"),
    lambda p: p["fixes"][0].update(requires="restart"),  # differs from the folder's fix.json
    lambda p: p["fixes"][0].update(client_impact="no"),
    lambda p: p.update(run_id="1" * 32),  # the folders belong to another run
    lambda p: p.update(run_id="../../etc"),
    lambda p: p.update(database="otherdb"),
    lambda p: p.update(fixes=[]),
    lambda p: p.update(schema_version="other"),
])
def test_a_package_json_that_does_not_match_the_folders_is_refused(rig, change):
    rig.package()
    rewrite_package(rig.base, change)
    assert rig.run(*APPLY) == pr.EXIT_REFUSED
    assert rig.log == []


def test_a_fix_folder_that_is_a_symlink_is_refused(rig, tmp_path):
    rig.package()
    real = rig.base / "fix-log_connections"
    moved = tmp_path / "moved"
    real.rename(moved)
    real.symlink_to(moved, target_is_directory=True)
    assert rig.run(*APPLY) == pr.EXIT_REFUSED
    assert rig.log == []


@pytest.mark.parametrize("state", [
    "not json", json.dumps({"schema_version": pr.STATE_SCHEMA, "run_id": "2" * 32, "applied": []}),
    json.dumps({"schema_version": pr.STATE_SCHEMA, "run_id": RUN_ID,
                "applied": [{"fix_id": "fix-log_disconnections", "status": "verified"}]}),  # not the package order
    json.dumps({"schema_version": pr.STATE_SCHEMA, "run_id": RUN_ID,
                "applied": [{"fix_id": "fix-log_connections", "status": "whatever"}]}),
])
def test_a_state_file_that_does_not_match_the_package_is_refused(rig, state):
    rig.package()
    (rig.base / pr.STATE_FILE).write_text(state)
    for argv in (APPLY, ("rollback-all",), ("verify-all",), ("status",)):
        assert rig.run(*argv) == pr.EXIT_REFUSED
    assert rig.log == []


def test_two_package_commands_cannot_run_at_once(rig):
    rig.package()
    with pr._Lock(rig.base):
        assert rig.run(*APPLY) == pr.EXIT_REFUSED
    assert rig.log == [] and "Another package command" in rig.err


def test_an_unexpected_error_is_never_echoed(rig, monkeypatch):
    rig.package()
    monkeypatch.setattr(pr, "load_state", lambda *a: (_ for _ in ()).throw(ValueError("secret " + DSN)))
    assert rig.run(*APPLY) == pr.EXIT_FAILED
    assert "secret" not in rig.out + rig.err and "s3cr3t" not in rig.out + rig.err


# ---------------------------------------------------------------------------
# The real subprocess path: an argv list, never a shell
# ---------------------------------------------------------------------------

STAND_IN = '''import json, os, sys
if sys.argv[1] == "rollback":
    print("Configuration drift detected; no SQL executed.", file=sys.stderr)
    sys.exit(1)
print("log line that is not JSON")
print(json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd(), "verified": True,
                  "has_dsn": bool(os.environ.get("DBGUARD_DSN"))}))
'''


def test_run_fix_starts_the_folders_own_runner_with_an_argv_list(tmp_path, monkeypatch):
    base = make_package(tmp_path / "package", THREE[:1], runner_source=STAND_IN)
    monkeypatch.setenv("DBGUARD_DSN", DSN)
    calls = []
    real = subprocess.run
    monkeypatch.setattr(subprocess, "run", lambda argv, **k: calls.append((argv, k)) or real(argv, **k))
    item = pr.load_package(base)["fixes"][0]
    outcome = pr.run_fix(base, item, "apply", dsn=DSN, allow_demo=True, ack=True, evidence_dir=base / "ev")
    argv, kwargs = calls[0]
    assert isinstance(argv, list) and "shell" not in kwargs
    assert argv[0] == sys.executable and argv[1] == str(base / "fix-log_connections" / "runner.py")
    assert argv[2:] == ["apply", "fix-log_connections", "--evidence-dir", str(base / "ev" / "runner"),
                        "--ack-prerequisites", "--allow-demo"]
    assert DSN not in " ".join(argv)  # the DSN travels only in the environment
    assert outcome["ok"] is True and outcome["result"]["has_dsn"] is True
    assert os.path.realpath(outcome["result"]["cwd"]) == os.path.realpath(base)
    status = pr.run_fix(base, item, "status", dsn=DSN, evidence_dir=base / "ev")
    assert status["result"]["argv"] == ["status", "fix-log_connections", "--evidence-dir", str(base / "ev" / "runner")]
    failed = pr.run_fix(base, item, "rollback", dsn=DSN, evidence_dir=base / "ev")
    assert failed == {"ok": False, "result": None, "message": "Configuration drift detected; no SQL executed."}


def test_a_runner_that_never_finishes_is_a_failure_not_a_crash(tmp_path, monkeypatch):
    base = make_package(tmp_path / "package", THREE[:1], runner_source="import time\ntime.sleep(30)\n")
    monkeypatch.setattr(pr, "RUNNER_TIMEOUT_SECONDS", 1)
    outcome = pr.run_fix(base, pr.load_package(base)["fixes"][0], "apply", dsn=DSN, evidence_dir=base / "ev")
    assert outcome["ok"] is False and "did not finish in time" in outcome["message"]


def test_harden_sh_runs_the_package_runner_with_the_stdlib_only(tmp_path):
    """The real harden.sh and assets, a system python3 and no DBGUARD_DSN: refused (exit 2)
    before psycopg2 or any other third-party module is needed."""
    base = make_package(tmp_path / "package", THREE[:1])
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    done = subprocess.run(["sh", str(base / "harden.sh"), "status"], capture_output=True, text=True, env=env,
                          cwd=str(tmp_path), timeout=60)
    assert done.returncode == pr.EXIT_REFUSED, done.stderr
    assert "DBGUARD_DSN" in done.stderr
    usage = subprocess.run(["sh", str(base / "harden.sh"), "apply-everything"], capture_output=True, text=True,
                           env=env, timeout=60)
    assert usage.returncode == 2


THIRD_PARTY_ALLOWED = {"psycopg2", "playwright"}


@pytest.mark.parametrize("name", ["package_runner.py", "terminal_evidence.py", "visual_evidence.py", "runner.py"])
def test_bundle_assets_import_only_the_stdlib_psycopg2_and_playwright(name):
    tree = ast.parse((ASSETS / name).read_text())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules.add(node.module.split(".")[0])
    siblings = {"terminal_evidence", "visual_evidence"}
    outside = {m for m in modules if m not in sys.stdlib_module_names} - THIRD_PARTY_ALLOWED - siblings
    assert outside == set()


# ---------------------------------------------------------------------------
# package_assets: what batch.py writes at the top of the combined package
# ---------------------------------------------------------------------------

def test_package_files_are_the_runner_assets_and_a_top_level_harden_sh():
    files = package_assets.package_files()
    assert set(files) == {"harden.sh", "package_runner.py", "terminal_evidence.py", "visual_evidence.py"}
    assert files["harden.sh"].startswith(b"#!/bin/sh\nset -eu\n")
    assert b'exec python3 "$PACKAGE_DIR/package_runner.py" "$@"' in files["harden.sh"]
    for name in package_assets.ASSET_FILES:
        assert files[name] == (ASSETS / name).read_bytes()


def test_package_json_has_the_shape_the_runner_reads():
    package = json.loads(package_assets.package_json(RUN_ID, "appdb", THREE, target_id="target-01",
                                                     system_identifier=7300000000000000001))
    assert package == {
        "schema_version": "dbguard-package-v1", "run_id": RUN_ID, "database": "appdb",
        "system_identifier": "7300000000000000001", "target_id": "target-01", "demo_fixture_approval": False,
        "fixes": [{"fix_id": f["fix_id"], "folder": f["fix_id"], "requires": f["requires"], "client_impact": False}
                  for f in THREE]}


@pytest.mark.parametrize("bad", [
    dict(run_id="nope"), dict(database=""), dict(fixes=[]),
    dict(fixes=[{"fix_id": "fix-a", "requires": "reload"}]),  # client_impact missing
    dict(fixes=[{"fix_id": "fix-a", "requires": "sometimes", "client_impact": False}]),
    dict(fixes=[{"fix_id": "fix-a;rm", "requires": "reload", "client_impact": False}]),
    dict(fixes=[{"fix_id": "fix-a", "folder": "../a", "requires": "reload", "client_impact": False}]),
    dict(fixes=[{"fix_id": "fix-a", "requires": "reload", "client_impact": False}] * 2),
])
def test_package_json_refuses_what_the_runner_would_refuse(bad):
    args = {"run_id": RUN_ID, "database": "appdb", "fixes": THREE}
    args.update(bad)
    with pytest.raises(ContractError):
        package_assets.package_json(args["run_id"], args["database"], args["fixes"])


def test_object_fix_ids_are_valid_package_entries():
    object_fix = {"fix_id": "fix-4.6-table_revoke_dml-0123abcdef", "requires": None, "client_impact": False}
    package = json.loads(package_assets.package_json(RUN_ID, "appdb", [object_fix]))
    assert package["fixes"][0] == {"fix_id": object_fix["fix_id"], "folder": object_fix["fix_id"],
                                   "requires": "none", "client_impact": False}


def test_manifest_entries_cover_the_required_files_and_only_allowed_names():
    files = dict(package_assets.package_files(), **{"package.json": b"{}", "report.html": b"<p>",
                                                    "README.txt": b"x", "fix-a/fix.json": b"{}"})
    entries = package_assets.manifest_entries(files)
    assert set(entries) == set(package_assets.REQUIRED_FILES) | {"report.html"}
    assert entries["package.json"] == sha(b"{}")
    del files["package.json"]
    with pytest.raises(ContractError):
        package_assets.manifest_entries(files)


def test_readme_text_covers_the_gate_requirements():
    text = package_assets.readme_text([THREE[0], fix("fix-ssl_min_protocol_version", "reload", True), THREE[2]])
    for needed in ("sh harden.sh status", "sh harden.sh apply-all --ack-prerequisites --ack-client-impact",
                   "sh harden.sh verify-all", "sh harden.sh rollback-all",
                   "DBGuard never connects to your database; this package does when you run it.",
                   pr.RESTART_LINE, pr.RESTART_ROLLBACK_LINE, "never restarts PostgreSQL",
                   "single-user machine", "VHS, ttyd, ffmpeg and psql", "Python 3 and psycopg2",
                   "Run VHS once while online", "STOPS AT THE FIRST PROBLEM", "ONLY the fixes this package applied",
                   "These fixes need a PostgreSQL restart: fix-logging_collector.",
                   "Required here for: fix-ssl_min_protocol_version.", "pg_hba.conf", "target-evidence-<run>.zip",
                   "fix-log_connections, fix-ssl_min_protocol_version, fix-logging_collector"):
        assert needed in text, needed
    assert "--allow-demo" not in text
    assert "sh harden.sh apply-all --ack-prerequisites --ack-client-impact --allow-demo" in \
        package_assets.readme_text(THREE, demo=True)
    assert "No fix in this package needs a restart." in package_assets.readme_text(THREE[:2])


def test_connection_errors_never_show_a_host_or_user_from_the_pg_environment(monkeypatch):
    # Security review finding 3: libpq may take host/user from PG* variables, not DBGUARD_DSN.
    monkeypatch.setenv("PGHOST", "db.internal")
    monkeypatch.setenv("PGUSER", "admin_x")
    line = 'connection to server at "db.internal" (10.0.0.5), port 5432 failed: FATAL: user "admin_x"'
    assert pr.safe_message(line, "dbname=prod") == pr.WITHHELD
    assert pr.safe_message("refused: db.internal is busy", "dbname=prod") == pr.WITHHELD
    assert pr.safe_message("refused: admin_x lacks rights", "dbname=prod") == pr.WITHHELD


# ---------------------------------------------------------------------------
# A second restart round (fix of 16 Nov): e.g. 5.6 passwordcheck then 3.2 pgaudit, both in
# shared_preload_libraries. The sandbox restarts between them, so the package pauses there.
# ---------------------------------------------------------------------------

ROUNDS = [
    {"fix_id": "fix-log_connections", "folder": "fix-log_connections", "requires": "reload",
     "client_impact": False, "setting": "log_connections"},
    {"fix_id": "fix-passwordcheck", "folder": "fix-passwordcheck", "requires": "restart",
     "client_impact": False, "setting": "shared_preload_libraries", "restart_round": 1},
    {"fix_id": "fix-pgaudit", "folder": "fix-pgaudit", "requires": "restart",
     "client_impact": False, "setting": "shared_preload_libraries", "restart_round": 2},
]


def test_apply_all_pauses_before_a_later_restart_round(rig):
    rig.package(fixes=ROUNDS, restart={"fix-passwordcheck", "fix-pgaudit"})
    assert rig.run(*APPLY) == pr.EXIT_RESTART
    assert rig.runner.actions("apply") == ["fix-log_connections", "fix-passwordcheck"]
    assert pr.RESTART_CONTINUE_LINE in rig.out and "Not applied yet" in rig.out and "fix-pgaudit" in rig.out
    assert [e["status"] for e in rig.state()["applied"]] == [pr.VERIFIED, pr.RESTART_PENDING]


def test_apply_all_again_verifies_the_restarted_round_then_continues(rig):
    rig.package(fixes=ROUNDS, restart={"fix-passwordcheck", "fix-pgaudit"})
    rig.run(*APPLY)
    del rig.log[:]
    assert rig.run(*APPLY) == pr.EXIT_RESTART  # pgaudit itself still needs its restart
    assert rig.log[:2] == [("verify", "fix-passwordcheck"), ("apply", "fix-pgaudit")]
    assert pr.RESTART_LINE in rig.out
    assert [e["status"] for e in rig.state()["applied"]] == [pr.VERIFIED, pr.VERIFIED, pr.RESTART_PENDING]
    assert rig.run("verify-all") == pr.EXIT_OK


def test_apply_all_again_without_the_restart_refuses_and_applies_nothing(rig):
    rig.package(fixes=ROUNDS, restart={"fix-passwordcheck", "fix-pgaudit"},
                script={("verify", "fix-passwordcheck"): FAIL})
    rig.run(*APPLY)
    assert rig.run(*APPLY) == pr.EXIT_REFUSED
    assert "Restart PostgreSQL first" in (rig.out + rig.err)
    assert "fix-pgaudit" not in rig.runner.actions("apply")


def test_a_round_is_only_accepted_on_a_restart_fix():
    from services.sandbox_poc.shared import ContractError
    bad = [{**ROUNDS[0], "restart_round": 2}]
    with pytest.raises(ContractError):
        package_assets.package_json("0123456789abcdef0123456789abcdef", "appdb", bad)
    readme = package_assets.readme_text(ROUNDS)
    assert pr.RESTART_CONTINUE_LINE in readme
    assert pr.RESTART_CONTINUE_LINE not in package_assets.readme_text(THREE)


def test_verify_all_does_not_recheck_a_fix_a_later_fix_extended(rig):
    # Fix of 16 Nov: 3.2 pgaudit appends to the preload list 5.6 passwordcheck wrote, so
    # passwordcheck's own "after" state is gone by design. It was verified when it took effect;
    # pgaudit's check covers the final value. Its stale re-check must not stop verify-all.
    rig.package(fixes=ROUNDS, restart={"fix-passwordcheck", "fix-pgaudit"},
                script={("verify", "fix-passwordcheck"): {"ok": True, "message": "",
                                                          "result": {"verified": True}}})
    rig.run(*APPLY)
    rig.run(*APPLY)
    rig.runner.script[("verify", "fix-passwordcheck")] = FAIL
    del rig.log[:]
    assert rig.run("verify-all") == pr.EXIT_OK
    assert ("verify", "fix-passwordcheck") not in rig.log and ("verify", "fix-pgaudit") in rig.log
    assert "fix-pgaudit then changed the same settings" in rig.out


def test_verify_all_still_rechecks_fixes_nothing_later_touched(rig):
    rig.package(fixes=ROUNDS, restart={"fix-passwordcheck", "fix-pgaudit"})
    rig.run(*APPLY)
    rig.run(*APPLY)
    rig.runner.script[("verify", "fix-log_connections")] = FAIL
    assert rig.run("verify-all") == pr.EXIT_FAILED
    assert "STOPPED at fix-log_connections" in rig.out


def test_apply_all_pauses_after_every_restart_fix_even_in_one_round(rig):
    # Fix of 16 Nov (live test): logging_collector and passwordcheck were restarted together in
    # the sandbox, but passwordcheck's guard expects logging_collector ACTIVE, so the package
    # pauses for a restart after each restart fix.
    same_round = [ROUNDS[0],
                  {**ROUNDS[1], "fix_id": "fix-logging_collector", "folder": "fix-logging_collector",
                   "setting": "logging_collector"},
                  {**ROUNDS[1]}]
    rig.package(fixes=same_round, restart={"fix-logging_collector", "fix-passwordcheck"})
    assert rig.run(*APPLY) == pr.EXIT_RESTART
    assert rig.runner.actions("apply") == ["fix-log_connections", "fix-logging_collector"]
    assert "then run: sh harden.sh apply-all --ack-prerequisites --ack-client-impact" in rig.out
    assert rig.run(*APPLY) == pr.EXIT_RESTART
    assert rig.runner.actions("apply")[-1] == "fix-passwordcheck" and pr.RESTART_LINE in rig.out
