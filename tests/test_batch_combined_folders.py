"""Package folders built from the combined test's records (Melvin's ruling of 12 Nov 2026).

The real spec engine, the real SandboxService.prepare and the real folder builder
(review_bundle.build_combined_fix_files) with fake setting runtimes: no Docker. Checks
that each fix folder is what the per-fix runner and the package runner accept, that it is
built from the final VERIFIED combined test (not a single test), and that the builder
refuses records that do not prove the fix.
"""
import copy
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from dataclasses import replace
from unittest.mock import Mock

import pytest

from scripts.sandbox_poc import demo_template
from services.sandbox_poc import batch, review_bundle
from services.sandbox_poc.bundle_assets import package_runner
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ContractError, SpecEngine, digest
from services.sandbox_poc.workflow import CONTROL
from test_sandbox_guard_scope import S3125, SettingRuntime
from test_sandbox_poc import engine, snapshot  # noqa: F401  (shared fixtures)

# The per-fix runner's manifest allowlist (bundle_assets/runner.py main()).
RUNNER_MEMBERS = {"fix.json", "evidence.json", "report.html", "harden.sh", "runner.py", "risk-review.json",
                  "verify.sh", "visual_evidence.py", "sandbox-after.png", "sandbox-queries.json",
                  "screenshots/before.png", "screenshots/after.png", "screenshots/rollback.png"}
SETTING_RUNNER_KEYS = {"fix_id", "database", "demo_fixture_approval", "names", "prior", "applied", "run_id",
                       "control_id", "setting", "requires", "target_id", "system_identifier", "spec_set_hash",
                       "snapshot_hash", "policy_profile", "apply_statements", "rollback_statements",
                       "combined_run_id", "client_impact"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run_setting_batch(engine, source, tmp_path, monkeypatch, spy=None):  # noqa: F811
    """3.1.20 + 3.1.25 through the real service; every runtime is a fake setting runtime."""
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
    by_setting = {s["check"]["setting_name"]: s["spec_id"] for s in engine.specs
                  if s.get("check", {}).get("kind") == "setting"}
    runtimes = []

    def factory():
        runtimes.append(SettingRuntime(source, len(runtimes) + 1, by_setting))
        return runtimes[-1]
    template = demo_template()
    ref = TemplateReference(version=template.version, sha256=template.sha256,
                            evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
    approved = replace(template, approved_by="unit-reviewer", evidence=tuple(
        {**e.model_dump(), "approved_by": "unit-reviewer"} for e in ref.evidence))
    service = SandboxService("unused", registry_loader=Mock(return_value=approved), runtime_factory=factory)
    service.run = Mock(side_effect=AssertionError("no single test may run when the combined test passes"))
    if spy is not None:
        monkeypatch.setattr(batch, "build_combined_fix_files", spy)
    base = build_handoff(engine, source, ref).model_dump()
    requests = [SandboxHandoff(**{**base, "control_id": c, "retry_mode": "repeat"}) for c in (CONTROL, S3125)]
    output, data = batch.run_batch(requests, service)
    return output, data, runtimes, requests


class TestFoldersFromCombinedRecords:
    def test_prepare_starts_no_sandbox_and_binds_the_approved_template(self, engine, snapshot):  # noqa: F811
        runtimes = []
        template = demo_template()
        ref = TemplateReference(version=template.version, sha256=template.sha256,
                                evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
        service = SandboxService("unused", registry_loader=Mock(return_value=template),
                                 runtime_factory=lambda: runtimes.append(1))
        handoff = build_handoff(engine, snapshot, ref)
        prepared = service.prepare(handoff)
        assert runtimes == [] and prepared["status"] == "PREPARED" and "attempts" not in prepared
        assert prepared["fix_unit_hash"] == digest(prepared["fix_unit"])
        assert prepared["snapshot_hash"] == digest(snapshot) and prepared["approval_source"] == "registry"
        assert prepared["rendered_apply_sql"] == template.render("log_connections", "on")
        assert prepared["risk_review"]["fix_id"] == prepared["fix_unit"]["fix_id"] == "fix-log_connections"
        # The single run's own checks still apply before anything is prepared.
        passing = copy.deepcopy(snapshot)
        passing["checks"][CONTROL]["result"] = "on"
        with pytest.raises(ContractError, match="must be FAIL"):
            service.prepare(build_handoff(engine, passing, ref))
        with pytest.raises(ContractError, match="Adaptive retries require"):
            service.prepare(handoff.model_copy(update={"retry_mode": "adaptive"}))

    def test_every_folder_is_runner_valid_and_from_the_combined_test(self, engine, snapshot, tmp_path,  # noqa: F811
                                                                     monkeypatch):
        output, data, runtimes, _ = run_setting_batch(engine, snapshot, tmp_path, monkeypatch)
        assert output["status"] == "VERIFIED", output.get("combined_test", {}).get("reason")
        assert output["individual_runs"] == [] and len(runtimes) == 1
        combined_id = output["combined_test"]["run_id"]
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        order = json.loads(files["package.json"])["fixes"]
        assert [f["fix_id"] for f in order] == output["recommended_order"] == ["fix-log_connections",
                                                                               "fix-log_statement"]
        configs = []
        for item in order:
            prefix = item["folder"] + "/"
            members = {n[len(prefix):]: v for n, v in files.items() if n.startswith(prefix)}
            manifest = json.loads(members["manifest.json"])
            assert set(manifest["files"]) <= RUNNER_MEMBERS
            assert set(members) == set(manifest["files"]) | {"manifest.json", "README.txt"}
            assert all(sha(members[n]) == h for n, h in manifest["files"].items())
            assert manifest["run_id"] == combined_id
            config = json.loads(members["fix.json"])
            assert SETTING_RUNNER_KEYS <= set(config) and config["fix_id"] == item["fix_id"]
            assert config["run_id"] == combined_id and config["combined_run_id"] == output["run_id"]
            assert config["requires"] == item["requires"] == "reload" and config["database"]
            assert config["apply_statements"] and config["rollback_statements"]
            assert config["prior"] != config["applied"]
            configs.append(config)
            report = members["report.html"].decode()
            assert f"Tested in the combined run {combined_id}" in report and "VERIFIED in the combined test" in report
            evidence = json.loads(members["evidence.json"])
            assert evidence["combined_test"]["step"]["fix_id"] == item["fix_id"]
            assert evidence["combined_test"]["rollback"] == [{"fix_id": item["fix_id"], "verified": True}]
            assert evidence["single_test"] is None and "result" not in evidence
        # The guard chain: the second fix expects the first one to remain applied.
        first, second = configs
        assert first["names"] == second["names"]
        assert second["prior"] == first["applied"]
        assert first["prior"]["settings"]["log_connections"]["setting"] == "off"
        assert first["applied"]["settings"]["log_connections"]["setting"] == "on"
        # The package runner accepts the package; the per-fix runner accepts its manifest.
        folder = tmp_path / "package"
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive.extractall(folder)
        package = package_runner.load_package(folder)
        assert [f["fix_id"] for f in package["fixes"]] == [f["fix_id"] for f in order]
        fix_dir = folder / order[0]["folder"]
        out = subprocess.run([sys.executable, "-I", str(fix_dir / "runner.py"), "status", order[0]["fix_id"]],
                             cwd=fix_dir, env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=60)
        assert out.returncode == 1 and "Set DBGUARD_DSN explicitly" in out.stderr, out.stderr


class TestTheBuilderRefusesUnprovenRecords:
    @pytest.fixture
    def captured(self, engine, snapshot, tmp_path, monkeypatch):  # noqa: F811
        calls = []
        real = review_bundle.build_combined_fix_files

        def spy(*args, **kwargs):
            calls.append((copy.deepcopy(args), dict(kwargs)))
            return real(*args, **kwargs)
        output, data, _, _ = run_setting_batch(engine, snapshot, tmp_path, monkeypatch, spy=spy)
        assert output["status"] == "VERIFIED" and data and len(calls) == 2
        args, kwargs = calls[0]
        assert review_bundle.build_combined_fix_files(*args, **kwargs)["fix.json"]
        return args, kwargs

    @staticmethod
    def build(args, kwargs, change):
        handoff, prepared, step, record, engine = copy.deepcopy(args[:4]) + (args[4],)  # noqa: F811
        change(prepared, step, record)
        return review_bundle.build_combined_fix_files(handoff, prepared, step, record, engine, **kwargs)

    @pytest.mark.parametrize("change,message", [
        (lambda p, s, r: r.update(status="FAILED"), "VERIFIED combined test"),
        (lambda p, s, r: r.update(cleanup={"verified": False}), "removal was verified"),
        (lambda p, s, r: r["rollback"][-1].update(verified=False), "exact undo of this fix"),
        (lambda p, s, r: r.update(rollback=[e for e in r["rollback"] if e["fix_id"] != s["fix_id"]]),
         "exact undo of this fix"),
        (lambda p, s, r: p.update(approval_source="model"), "registry approval"),
        (lambda p, s, r: p["fix_unit"]["apply"].update(value="off"), "fix-unit identity"),
        (lambda p, s, r: p.update(rendered_apply_sql=p["rendered_apply_sql"].replace("'on'", "'off'")),
         "typed action differs"),
        (lambda p, s, r: p["template"].update(sha256="b" * 64), "not pinned in the handoff"),
        (lambda p, s, r: s.update(fix_id="fix-other"), "combined step differs"),
        (lambda p, s, r: s["functional_checks"].update(passed=False), "functional checks"),
        (lambda p, s, r: s["assessment"]["findings"][CONTROL].update(status="FAIL"), "assessment does not match"),
    ])
    def test_tampered_records_are_refused(self, captured, change, message):
        args, kwargs = captured
        with pytest.raises(ContractError, match=message):
            self.build(args, kwargs, change)

    def test_a_fix_that_did_not_pass_its_step_is_refused(self, captured, engine):  # noqa: F811
        args, kwargs = captured

        def undo_the_fix(prepared, step, record):
            step["after"] = copy.deepcopy(step["before"])
            step["assessment"] = engine.assess(step["after"])
        with pytest.raises(ContractError, match="target did not pass"):
            self.build(args, kwargs, undo_the_fix)

    def test_the_single_test_is_reported_when_one_ran(self, captured):
        args, kwargs = captured
        files = review_bundle.build_combined_fix_files(*args, **{**kwargs, "single": {"run_id": "solo-1",
                                                                                     "status": "VERIFIED"}})
        assert "Also tested on its own in sandbox run solo-1: VERIFIED" in files["report.html"].decode()
        assert json.loads(files["evidence.json"])["single_test"] == {"run_id": "solo-1", "status": "VERIFIED"}
