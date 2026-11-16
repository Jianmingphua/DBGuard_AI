"""Checks a DBA's target-evidence zip before it is stored (E2E Gate 1, decision 2).

The package's runner writes target-evidence-<run_id>.zip on the DBA's machine: up to three
pictures (before, after, rollback), the query output and the event record for each stage,
and a manifest with the sha256 of every file. The DBA uploads it on step 7. The zip is
untrusted input: this module accepts only the runner's fixed file names, PNG and JSON,
bounded sizes, fingerprints that match, and the run's own database and cluster identity.
A passing check means only "these files are internally consistent and name this run and its
database". It is NOT proof of origin: anyone holding the run ID could build a consistent zip
(security review finding 1). Whether the target is now hardened is decided by the server's
reassessment of a fresh snapshot, never here.
"""
import base64
import hashlib
import io
import json
import zipfile
import zlib

from .shared import ContractError

STAGES = ("before", "after", "rollback")
MEMBERS = frozenset([f"{s}.png" for s in STAGES] + [f"queries-{s}.json" for s in STAGES]
                    + [f"event-{s}.json" for s in STAGES] + ["manifest.json"])
SCHEMA = "dbguard-target-evidence-v1"
MAX_ZIP = 20 * 1024 * 1024
MAX_MEMBER = 8 * 1024 * 1024
MAX_TOTAL = 30 * 1024 * 1024
MAX_QUERIES = 512 * 1024  # serialized query output kept per stage
STATUS = "CONSISTENT_NOT_AUTHENTICATED"
PNG = b"\x89PNG\r\n\x1a\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(name: str, data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ContractError(f"{name} is not valid JSON") from None
    if not isinstance(value, dict):
        raise ContractError(f"{name} is not a JSON object")
    return value


def read_members(data: bytes) -> dict:
    """{name: bytes} of a size-checked zip holding only the runner's fixed file names."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ContractError("Upload the target-evidence zip the package wrote")
    if len(data) > MAX_ZIP:
        raise ContractError("The evidence zip is larger than 20 MB")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ContractError("The upload is not a zip file") from None
    with archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        if len(names) != len(set(names)):
            raise ContractError("The evidence zip repeats a file name")
        unexpected = sorted(n for n in names if n not in MEMBERS)
        if unexpected:
            raise ContractError("Unexpected file in the evidence zip: " + unexpected[0][:80])
        if sum(i.file_size for i in infos) > MAX_TOTAL or any(i.file_size > MAX_MEMBER for i in infos):
            raise ContractError("A file in the evidence zip is too large")
        members = {}
        for info in infos:
            # Review finding 4: encrypted, damaged or oddly compressed members are refused, not a 500.
            try:
                with archive.open(info) as handle:
                    content = handle.read(MAX_MEMBER + 1)
            except (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError, OSError):
                raise ContractError(f"{info.filename[:80]} in the evidence zip cannot be read") from None
            if len(content) > MAX_MEMBER or len(content) != info.file_size:
                raise ContractError("A file in the evidence zip is too large or damaged")
            members[info.filename] = content
    if "manifest.json" not in members:
        raise ContractError("The evidence zip has no manifest.json")
    return members


def check(data: bytes, run_id: str, record: dict) -> dict:
    """The stored receipt for a valid upload; raises ContractError with the reason otherwise.

    ``record`` is history.get(run_id): the expected database and cluster identity come from
    the run's own snapshot, never from the upload.
    """
    members = read_members(data)
    manifest = _json("manifest.json", members["manifest.json"])
    if manifest.get("schema_version") != SCHEMA:
        raise ContractError("manifest.json is not a DBGuard target-evidence manifest")
    if manifest.get("run_id") != run_id:
        raise ContractError("This evidence belongs to a different run")
    files = manifest.get("files")
    others = {n for n in members if n != "manifest.json"}
    if not isinstance(files, dict) or set(files) != others:
        raise ContractError("manifest.json does not list exactly the files in the zip")
    for name in sorted(others):
        if files[name] != _sha(members[name]):
            raise ContractError(f"{name} does not match its fingerprint in manifest.json")
    snapshot = (record.get("handoff") or {}).get("snapshot") or {}
    expected_db = (snapshot.get("envelope") or {}).get("database")
    expected_id = ((snapshot.get("baseline") or {}).get("identity") or {}).get("system_identifier")
    if not expected_db or not expected_id:
        raise ContractError("The run has no recorded database and cluster identity to compare with")
    if manifest.get("identity_consistent") is not True:
        raise ContractError("The pictures were taken on more than one database")
    if manifest.get("database") != expected_db or str(manifest.get("system_identifier")) != str(expected_id):
        raise ContractError("This evidence was recorded on a different database or cluster than the run")
    stages = {}
    for stage in STAGES:
        event_name, png_name, query_name = f"event-{stage}.json", f"{stage}.png", f"queries-{stage}.json"
        if event_name not in members:
            if png_name in members or query_name in members:
                raise ContractError(f"{stage}: picture or query output without its event record")
            continue
        event = _json(event_name, members[event_name])
        if (event.get("run_id") != run_id or event.get("stage") != stage
                or event.get("database") != expected_db
                or str(event.get("system_identifier")) != str(expected_id)):
            raise ContractError(f"{event_name} does not match this run and database")
        png = members.get(png_name)
        if png is not None:
            if not png.startswith(PNG):
                raise ContractError(f"{png_name} is not a PNG image")
            if event.get("png_sha256") != _sha(png):
                raise ContractError(f"{png_name} does not match its event record")
        elif event.get("png_sha256"):
            raise ContractError(f"{png_name} is missing")
        queries = _json(query_name, members[query_name]) if query_name in members else None
        if queries is not None and (queries.get("run_id") != run_id or queries.get("stage") != stage):
            raise ContractError(f"{query_name} does not match this run")
        output = queries.get("queries") if queries is not None else None
        if output is not None and (not isinstance(output, (list, dict))
                                   or len(json.dumps(output)) > MAX_QUERIES):
            raise ContractError(f"{query_name}: query output is malformed or larger than 512 KB")
        step = event.get("step") if isinstance(event.get("step"), dict) else {}
        stages[stage] = {
            "mode": event.get("mode") if event.get("mode") in ("terminal", "rendered", "off") else None,
            "capture_status": str(event.get("status") or "")[:40] or None,
            "reason": str(event.get("reason"))[:300] if event.get("reason") else None,
            "captured_at": str(event.get("captured_at") or "")[:40] or None,
            "step": {**{k: str(v)[:200] for k, v in step.items() if k in ("command", "result", "started_at")},
                     "fixes": [{k: str(f.get(k))[:200] for k in ("fix_id", "result") if f.get(k) is not None}
                               for f in step.get("fixes", []) if isinstance(f, dict)][:200]
                     if isinstance(step.get("fixes"), list) else []},
            "typed_command": str(event.get("typed_command"))[:300] if event.get("typed_command") else None,
            "png_sha256": event.get("png_sha256"),
            "png_base64": base64.b64encode(png).decode() if png is not None else None,
            "queries": output,
        }
    if not stages:
        raise ContractError("The evidence zip has no stage records")
    return {"status": STATUS, "run_id": run_id, "database": expected_db,
            "system_identifier": str(expected_id), "zip_sha256": _sha(bytes(data)),
            "created_at": str(manifest.get("created_at") or "")[:40] or None,
            "scope": ("These files are internally consistent and name this run and its database. "
                      "They are not authenticated: they show what the DBA reports the package recorded. "
                      "Whether the database is now hardened is shown only by DBGuard's reassessment "
                      "of a fresh snapshot."),
            "stages": stages}


def public(receipt: dict, images: bool = True) -> dict:
    """The receipt for the UI; without picture data unless asked."""
    out = json.loads(json.dumps(receipt))
    if not images:
        for stage in out.get("stages", {}).values():
            stage.pop("png_base64", None)
            stage.pop("queries", None)
    return out
