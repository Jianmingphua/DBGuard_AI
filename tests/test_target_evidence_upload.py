"""Step 7 upload of the package's target-evidence zip (E2E Gate 1, decision 2).

The zip is untrusted. Only the runner's fixed names, PNG + JSON, bounded sizes, matching
fingerprints and the run's own database and cluster identity are accepted, and a passing
check never claims the target is hardened.
"""
import hashlib
import io
import json
import zipfile

import pytest

from services.sandbox_poc import target_evidence as te
from services.sandbox_poc.bundle_assets import terminal_evidence as writer
from services.sandbox_poc.shared import ContractError

RUN = "0123456789abcdef0123456789abcdef"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
RECORD = {"handoff": {"snapshot": {"envelope": {"database": "appdb", "target_id": "t1"},
                                   "baseline": {"identity": {"system_identifier": "7311"}}}},
          "result": {"run_id": RUN}, "events": []}


def shot(stage, png=PNG, database="appdb", sysid="7311", run=RUN):
    return {"stage": stage, "run_id": run, "status": "CAPTURED" if png else "UNAVAILABLE", "mode": "terminal",
            "png": png, "raw_output": [{"name": "log_connections", "setting": "on"}],
            "raw_output_sha256": "x", "captured_at": f"2026-11-12T00:00:0{len(stage)}Z",
            "database": database, "system_identifier": sysid, "target_id": "t1",
            "typed_command": "psql service=dbguard -X -e -v ON_ERROR_STOP=1 -f /tmp/x/dbguard-before.sql"}


def made_zip(tmp_path, *shots):
    for s in shots:
        writer.record_stage(tmp_path, s, {"command": "apply-all", "result": "VERIFIED",
                                          "fixes": [{"fix_id": "fix-a", "result": "VERIFIED"}]})
    return (tmp_path / f"target-evidence-{RUN}.zip").read_bytes()


def rezip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_the_packages_own_zip_is_accepted_with_pictures_and_steps(tmp_path):
    data = made_zip(tmp_path, shot("before"), shot("after"))
    receipt = te.check(data, RUN, RECORD)
    assert receipt["status"] == te.STATUS and set(receipt["stages"]) == {"before", "after"}
    assert receipt["stages"]["after"]["png_base64"] and receipt["stages"]["after"]["mode"] == "terminal"
    assert receipt["stages"]["before"]["step"]["fixes"] == [{"fix_id": "fix-a", "result": "VERIFIED"}]
    assert "not authenticated" in receipt["scope"] and "reassessment" in receipt["scope"] and receipt["zip_sha256"] == hashlib.sha256(data).hexdigest()
    slim = te.public(receipt, images=False)
    assert "png_base64" not in slim["stages"]["after"] and "queries" not in slim["stages"]["after"]


def test_a_changed_picture_is_refused(tmp_path):
    members = te.read_members(made_zip(tmp_path, shot("after")))
    members["after.png"] = PNG + b"tampered"
    with pytest.raises(ContractError, match="fingerprint"):
        te.check(rezip(members), RUN, RECORD)


def test_a_consistently_rehashed_but_swapped_picture_is_refused(tmp_path):
    members = te.read_members(made_zip(tmp_path, shot("after")))
    members["after.png"] = PNG + b"other"
    manifest = json.loads(members["manifest.json"])
    manifest["files"]["after.png"] = hashlib.sha256(members["after.png"]).hexdigest()
    members["manifest.json"] = json.dumps(manifest).encode()
    with pytest.raises(ContractError, match="event record"):
        te.check(rezip(members), RUN, RECORD)


@pytest.mark.parametrize("name", ["../evil.png", "after.jpg", "notes.txt", "screenshots/after.png", "/abs.json"])
def test_unexpected_names_are_refused(tmp_path, name):
    members = te.read_members(made_zip(tmp_path, shot("after")))
    members[name] = b"x"
    with pytest.raises(ContractError, match="Unexpected file"):
        te.check(rezip(members), RUN, RECORD)


def test_another_run_or_another_database_is_refused(tmp_path):
    with pytest.raises(ContractError, match="different run"):
        te.check(made_zip(tmp_path, shot("after")), "f" * 32, RECORD)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ContractError, match="different database"):
        te.check(made_zip(other, shot("after", database="otherdb")), RUN, RECORD)
    third = tmp_path / "third"
    third.mkdir()
    with pytest.raises(ContractError, match="different database"):
        te.check(made_zip(third, shot("after", sysid="999")), RUN, RECORD)


def test_pictures_from_two_databases_are_refused(tmp_path):
    data = made_zip(tmp_path, shot("before"), shot("after", database="otherdb"))
    with pytest.raises(ContractError, match="more than one database"):
        te.check(data, RUN, RECORD)


def test_a_run_without_recorded_identity_cannot_be_matched(tmp_path):
    record = {"handoff": {"snapshot": {"envelope": {"database": "appdb"}, "baseline": {}}}}
    with pytest.raises(ContractError, match="no recorded database and cluster identity"):
        te.check(made_zip(tmp_path, shot("after")), RUN, record)


def test_not_a_png_is_refused(tmp_path):
    members = te.read_members(made_zip(tmp_path, shot("after")))
    fake = b"GIF89a" + b"\x00" * 10
    members["after.png"] = fake
    event = json.loads(members["event-after.json"])
    event["png_sha256"] = hashlib.sha256(fake).hexdigest()
    members["event-after.json"] = json.dumps(event).encode()
    manifest = json.loads(members["manifest.json"])
    manifest["files"].update({"after.png": hashlib.sha256(fake).hexdigest(),
                              "event-after.json": hashlib.sha256(members["event-after.json"]).hexdigest()})
    members["manifest.json"] = json.dumps(manifest).encode()
    with pytest.raises(ContractError, match="not a PNG"):
        te.check(rezip(members), RUN, RECORD)


def test_size_limits_and_non_zips(tmp_path):
    with pytest.raises(ContractError, match="not a zip"):
        te.check(b"hello", RUN, RECORD)
    with pytest.raises(ContractError, match="larger than 20 MB"):
        te.check(b"x" * (te.MAX_ZIP + 1), RUN, RECORD)
    big = rezip({"manifest.json": b"{}", "after.png": PNG + b"\x00" * (te.MAX_MEMBER + 1)})
    with pytest.raises(ContractError, match="too large"):
        te.check(big, RUN, RECORD)


def test_manifest_must_list_exactly_the_files(tmp_path):
    members = te.read_members(made_zip(tmp_path, shot("after")))
    manifest = json.loads(members["manifest.json"])
    manifest["files"]["before.png"] = "0" * 64
    members["manifest.json"] = json.dumps(manifest).encode()
    with pytest.raises(ContractError, match="exactly the files"):
        te.check(rezip(members), RUN, RECORD)


def test_the_endpoints_store_and_return_the_upload(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from services.sandbox_poc import router as routes
    events = []
    monkeypatch.setattr(routes.history, "get", lambda run_id: {**RECORD, "events": events})
    monkeypatch.setattr(routes.history, "event",
                        lambda run_id, kind, data: events.append({"kind": kind, "data": data}))
    app = FastAPI()
    app.include_router(routes.router)
    client = TestClient(app)
    assert client.get(f"/api/v1/history/{RUN}/target-evidence").status_code == 404
    data = made_zip(tmp_path, shot("after"))
    up = client.post(f"/api/v1/history/{RUN}/target-evidence",
                     files={"file": ("target-evidence.zip", data, "application/zip")})
    assert up.status_code == 200 and up.json()["status"] == "CONSISTENT_NOT_AUTHENTICATED"
    assert "png_base64" not in up.json()["stages"]["after"]
    got = client.get(f"/api/v1/history/{RUN}/target-evidence").json()
    assert got["stages"]["after"]["png_base64"]
    bad = client.post(f"/api/v1/history/{RUN}/target-evidence",
                      files={"file": ("x.zip", b"nope", "application/zip")})
    assert bad.status_code == 422 and len(events) == 1


def test_malformed_members_are_refused_not_a_server_error(tmp_path):
    # Security review finding 4.
    deep = b"[" * 100000 + b"]" * 100000
    members = te.read_members(made_zip(tmp_path, shot("after")))
    members["queries-after.json"] = deep
    manifest = json.loads(members["manifest.json"])
    manifest["files"]["queries-after.json"] = hashlib.sha256(deep).hexdigest()
    members["manifest.json"] = json.dumps(manifest).encode()
    with pytest.raises(ContractError, match="not valid JSON"):
        te.check(rezip(members), RUN, RECORD)
    raw = bytearray(rezip({"manifest.json": b"{}" * 50}))
    raw[raw.index(b"{}") + 10] ^= 0xFF  # damage stored data so the CRC check fails
    with pytest.raises(ContractError):
        te.check(bytes(raw), RUN, RECORD)


def test_oversized_query_output_is_refused(tmp_path):
    big = shot("after")
    big["raw_output"] = [{"name": "x" * 1000}] * 700
    with pytest.raises(ContractError, match="larger than 512 KB"):
        te.check(made_zip(tmp_path, big), RUN, RECORD)
