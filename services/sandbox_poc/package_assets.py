"""Top-level files of the combined DBA package (E2E Gate 1, decision 2).

batch.py builds the combined zip; this module gives it the one-command runner's files, the
``package.json`` the runner reads, the README text and the manifest entries the runner
checks. Nothing here connects to a database or reads model output.

    files.update(package_files())
    files["package.json"] = package_json(run_id, database, fixes, ...)
    files["README.txt"] = (existing text + readme_text(fixes, demo)).encode()
    files["manifest.json"]["files"].update(manifest_entries(files))   # must cover REQUIRED_FILES
"""
import hashlib
import json
from pathlib import Path

from .bundle_assets import package_runner
from .shared import ContractError

ASSETS = Path(__file__).parent / "bundle_assets"

HARDEN_SH = (b'#!/bin/sh\nset -eu\nPACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
             b'exec python3 "$PACKAGE_DIR/package_runner.py" "$@"\n')

# Copied to the top of the combined package, next to the <fix_id>/ folders.
ASSET_FILES = ("package_runner.py", "terminal_evidence.py", "visual_evidence.py")
REQUIRED_FILES = package_runner.REQUIRED_FILES
TOP_LEVEL_FILES = package_runner.TOP_LEVEL_FILES
PACKAGE_SCHEMA = package_runner.PACKAGE_SCHEMA


def package_files() -> dict:
    """{name: bytes} of the runner's files: harden.sh plus ASSET_FILES."""
    files = {"harden.sh": HARDEN_SH}
    files.update({name: (ASSETS / name).read_bytes() for name in ASSET_FILES})
    return files


def package_json(run_id, database, fixes, *, system_identifier=None, target_id=None,
                 demo_fixture_approval=False) -> bytes:
    """The package description package_runner.py reads; refuses anything it would refuse.

    ``fixes`` is the apply order: [{fix_id, folder, requires: reload|restart|none,
    client_impact: bool}]. ``folder`` is the fix's top-level folder (today the fix_id).
    """
    if not isinstance(run_id, str) or not package_runner.RUN_ID.fullmatch(run_id):
        raise ContractError("Package: unexpected run ID")
    if not isinstance(database, str) or not database:
        raise ContractError("Package: database name is required")
    out, seen = [], set()
    for fix in fixes:
        fix_id, folder = fix.get("fix_id"), fix.get("folder", fix.get("fix_id"))
        requires, impact = fix.get("requires") or "none", fix.get("client_impact")
        rnd = fix.get("restart_round")
        if (not isinstance(fix_id, str) or not package_runner.FIX_ID.fullmatch(fix_id)
                or not isinstance(folder, str) or not package_runner.FOLDER.fullmatch(folder) or ".." in folder
                or fix_id in seen or folder in seen or requires not in package_runner.REQUIRES
                or not isinstance(impact, bool)
                or (rnd is not None and (requires != "restart" or type(rnd) is not int or not 1 <= rnd <= 10))):
            raise ContractError("Package: malformed fix entry")
        seen.update((fix_id, folder))
        out.append({"fix_id": fix_id, "folder": folder, "requires": requires, "client_impact": impact,
                    **({"restart_round": rnd} if rnd is not None else {})})
    if not out:
        raise ContractError("Package: no fixes")
    return json.dumps({"schema_version": PACKAGE_SCHEMA, "run_id": run_id, "database": database,
                       "system_identifier": None if system_identifier is None else str(system_identifier),
                       "target_id": target_id, "demo_fixture_approval": bool(demo_fixture_approval),
                       "fixes": out}, indent=2).encode()


def manifest_entries(files: dict) -> dict:
    """sha256 of every top-level file the runner's manifest check allows (README.txt and
    manifest.json excluded, as in the per-fix bundles). Raises if a required file is missing."""
    missing = [name for name in REQUIRED_FILES if name not in files]
    if missing:
        raise ContractError("Package: missing top-level file " + ", ".join(missing))
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()
            if name in TOP_LEVEL_FILES and name != "README.txt"}


def readme_text(fixes, demo=False) -> str:
    """The commands section of the combined package's README.txt (fixed text and fix IDs only)."""
    restart = [f["fix_id"] for f in fixes if f.get("requires") == "restart"]
    impact = [f["fix_id"] for f in fixes if f.get("client_impact")]
    demo_flag = " --allow-demo" if demo else ""
    lines = [
        "",
        "ONE COMMAND FOR THE WHOLE PACKAGE",
        "DBGuard never connects to your database; this package does when you run it.",
        "Set DBGUARD_DSN to the DBA-verified target using your normal credential handling. It is never",
        "printed, stored or pictured. No credentials are in this package.",
        "",
        "  sh harden.sh status" + demo_flag,
        "  sh harden.sh apply-all --ack-prerequisites --ack-client-impact" + demo_flag,
        "  sh harden.sh verify-all" + demo_flag,
        "  sh harden.sh rollback-all" + demo_flag,
        "",
        "status       shows each fix as applied, not applied or drift.",
        "apply-all    applies every fix in the tested order: " + ", ".join(f["fix_id"] for f in fixes) + ".",
        "             Each fix runs through its own folder's runner, so every check still applies: package",
        "             fingerprints, PostgreSQL 17 and database name, cluster identity, 'still as tested'",
        "             and the lock against two runs at once. It STOPS AT THE FIRST PROBLEM and lists what",
        "             was already applied. It keeps a small record, .dbguard-applied.json, in this folder.",
        "verify-all   confirms the fixes that needed a restart, lists the rest (verified in a fresh",
        "             connection when applied) and takes the after picture.",
        "rollback-all undoes ONLY the fixes this package applied, last applied first.",
        "",
        "--ack-prerequisites: you reviewed each fix's risk-review.json and checked its prerequisites.",
        "--ack-client-impact: you read CLIENT-ACTIONS.txt and prepared the affected clients."
        + (" Required here for: " + ", ".join(impact) + "." if impact else " Not required for this package."),
        "",
        "RESTART",
        ("These fixes need a PostgreSQL restart: " + ", ".join(restart) + "." if restart
         else "No fix in this package needs a restart."),
        "The package never restarts PostgreSQL. After writing restart fixes, apply-all ends with:",
        "  " + package_runner.RESTART_LINE,
        "Restart PostgreSQL yourself, then run that command.",
        ("With more than one restart fix, apply-all pauses for a restart after each one (each fix's safety "
         "check expects the ones before it to be active) and ends with:" if len(restart) > 1 else ""),
        ("  " + package_runner.RESTART_CONTINUE_LINE + " --ack-prerequisites ... (the same options as before)"
         if len(restart) > 1 else ""),
        "",
        "ROLLBACK",
        "rollback-all uses each fix's own rollback and refuses drift; it is not a disaster recovery tool.",
        "When a rollback needs a restart it stops there and ends with:",
        "  " + package_runner.RESTART_ROLLBACK_LINE,
        "Restart, run that command, then run rollback-all again until it reports every fix rolled back.",
        "",
        "EXIT CODES: 0 done; 1 a fix failed and the command stopped; 2 refused, nothing was run;",
        "3 restart PostgreSQL, then run the printed command.",
        "",
        "PICTURES AND EVIDENCE",
        "Three pictures of fixed, read-only checks are taken on your database: before (start of apply-all),",
        "after (end of verify-all) and after rollback. They show the changed settings and, for account or",
        "table fixes, that one object. They never ask for the server address, passwords or keys, and the",
        "address, user name and password are never typed or shown. The pictures, the query output and a",
        "fingerprint list are zipped as target-evidence/target-evidence-<run>.zip. Upload that zip on",
        "DBGuard's 'Verify target' step. A picture problem never fails a fix; the reason is recorded.",
        "  --screenshots terminal   (default) a real terminal recording; falls back to rendered",
        "  --screenshots rendered   a rendered page of the same query output",
        "  --screenshots off        no picture; the query output is still recorded",
        "  --evidence-dir DIR       where pictures and the zip are written",
        "",
        "PREREQUISITES",
        "Python 3 and psycopg2 (pip install psycopg2-binary).",
        "Terminal pictures: VHS, ttyd, ffmpeg and psql, installed once (for example: brew install vhs ttyd",
        "ffmpeg libpq), with psql at a standard system path. Run VHS once while online on any small tape so",
        "it fetches its browser; the package never lets it download one.",
        "Rendered pictures: pip install playwright; python3 -m playwright install chromium.",
        "If the terminal tools are missing the package takes a rendered picture and says why.",
        "",
        "WARNING: use terminal pictures only on a single-user machine. While a picture is recorded, a local",
        "terminal service listens on this machine for a few seconds, and a private connection file and",
        "password file exist in a temporary folder readable only by your account. Both are deleted straight",
        "after. On a shared machine use --screenshots rendered or --screenshots off.",
        "",
        "STILL MANUAL: login-rule file edits (pg_hba.conf), turning on TLS (certificates) and installing",
        "add-on packages are not done by this package.",
        "",
    ]
    return "\n".join(lines)
