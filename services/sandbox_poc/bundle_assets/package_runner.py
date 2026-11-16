"""One command for a DBGuard combined package, run by the DBA: status, apply-all, verify-all, rollback-all.

E2E Gate 1, decision 2 (Melvin, 10 Nov 2026). Needs Python 3 and psycopg2. DBGuard never
connects to the target; this script does, only when the DBA runs it with DBGUARD_DSN set.

- Every change is made by the fix's own ``<folder>/runner.py`` (argv list, no shell), so
  every existing guard still applies to each fix: manifest hashes, PostgreSQL 17 and
  database name, cluster identity, the DBGuard advisory lock, "still as tested" (drift),
  statement shapes, the preload LOAD check, one transaction for object fixes.
- ``apply-all`` follows package.json's order and stops at the first fix that does not
  succeed. It records what it applied in ``.dbguard-applied.json`` in this folder.
- ``rollback-all`` only touches fixes recorded there, last applied first.
- Nothing here restarts PostgreSQL. Restart-required fixes end with RESTART_LINE.
- Pictures (terminal_evidence.py) are taken before apply-all, after verify-all and after the
  last rollback. A picture problem never changes a result. DBGUARD_DSN is never printed.

Exit codes: 0 done; 1 a fix failed (stopped); 2 refused before anything ran; 3 restart
PostgreSQL, then run the printed command.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PACKAGE_SCHEMA = "dbguard-package-v1"
STATE_SCHEMA = "dbguard-package-state-v1"
STATE_FILE = ".dbguard-applied.json"
LOCK_FILE = ".dbguard-package.lock"
RESTART_LINE = "RESTART POSTGRESQL NOW, then run: sh harden.sh verify-all"
# A later restart round builds on an earlier one (e.g. a second add-on in the preload list),
# exactly as the sandbox restarted between them.
RESTART_CONTINUE_LINE = "RESTART POSTGRESQL NOW, then run: sh harden.sh apply-all"


def continue_line(args):
    """The exact apply-all command to run after the restart, with the acknowledgements given."""
    flags = ["--ack-prerequisites"]
    if getattr(args, "ack_client_impact", False):
        flags.append("--ack-client-impact")
    if getattr(args, "allow_demo", False):
        flags.append("--allow-demo")
    return RESTART_CONTINUE_LINE + " " + " ".join(flags)
RESTART_ROLLBACK_LINE = "RESTART POSTGRESQL NOW, then run: sh harden.sh verify-all --rollback"
EXIT_OK, EXIT_FAILED, EXIT_REFUSED, EXIT_RESTART = 0, 1, 2, 3
RUNNER_TIMEOUT_SECONDS = 900

VERIFIED, RESTART_PENDING, ROLLBACK_PENDING = "verified", "restart_pending", "rollback_restart_pending"
STATUSES = (VERIFIED, RESTART_PENDING, ROLLBACK_PENDING)

# The top-level manifest may list only these; the first five must be listed.
REQUIRED_FILES = ("package.json", "package_runner.py", "terminal_evidence.py", "visual_evidence.py", "harden.sh")
TOP_LEVEL_FILES = frozenset(REQUIRED_FILES + (
    "combined-evidence.json", "report.html", "README.txt", "CLIENT-ACTIONS.txt",
    "screenshots/combined-before.png", "screenshots/combined-after.png", "screenshots/combined-rollback.png"))

RUN_ID = re.compile(r"[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
FIX_ID = re.compile(r"fix-[A-Za-z0-9_.-]{1,120}")
FOLDER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
REQUIRES = ("reload", "restart", "none")
SAFE_MESSAGE = re.compile(r"[ -~]{1,400}")
WITHHELD = "The fix runner failed. Its message is withheld because it may hold connection details."


class Refused(Exception):
    """Nothing was run; the message is fixed text plus names from the checked package."""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _evidence_module():
    try:
        from . import terminal_evidence  # imported as part of the services package (tests)
    except ImportError:
        import terminal_evidence  # the package folder, next to this file
    return terminal_evidence


# ---------------------------------------------------------------------------
# The package: manifest, package.json and each fix folder
# ---------------------------------------------------------------------------

def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _read_json(path, what):
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        raise Refused(f"{what} is missing or not valid JSON; download the package again") from None
    if not isinstance(value, dict):
        raise Refused(f"{what} is malformed; download the package again")
    return value


def load_package(base):
    """The checked package: {run_id, target_id, database, fixes: [{fix_id, folder, requires,
    client_impact, config}]}. Refuses any file that differs from its manifest."""
    base = Path(base)
    manifest = _read_json(base / "manifest.json", "manifest.json")
    listed = manifest.get("files")
    if not isinstance(listed, dict):
        raise Refused("manifest.json is malformed; download the package again")
    for name, expected in listed.items():
        if name not in TOP_LEVEL_FILES:
            raise Refused("Unexpected package member in manifest.json")
        if not (base / name).is_file() or _sha256(base / name) != expected:
            raise Refused(f"Package content changed: {name}")
    for name in REQUIRED_FILES:
        if name not in listed:
            raise Refused(f"manifest.json does not cover {name}; download the package again")
    package = _read_json(base / "package.json", "package.json")
    run_id, fixes = package.get("run_id"), package.get("fixes")
    if package.get("schema_version") != PACKAGE_SCHEMA or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise Refused("package.json is not a DBGuard package description")
    if manifest.get("run_id") not in (None, run_id):
        raise Refused("package.json and manifest.json describe different runs")
    if not isinstance(fixes, list) or not fixes:
        raise Refused("package.json lists no fixes")
    out, seen = [], set()
    for item in fixes:
        if not isinstance(item, dict):
            raise Refused("package.json has a malformed fix entry")
        fix_id, folder = item.get("fix_id"), item.get("folder")
        if (not isinstance(fix_id, str) or not FIX_ID.fullmatch(fix_id) or not isinstance(folder, str)
                or not FOLDER.fullmatch(folder) or ".." in folder or folder in seen or fix_id in seen
                or item.get("requires") not in REQUIRES or not isinstance(item.get("client_impact"), bool)
                or ("restart_round" in item and (item["requires"] != "restart"
                                                 or type(item["restart_round"]) is not int
                                                 or not 1 <= item["restart_round"] <= 10))):
            raise Refused("package.json has a malformed fix entry")
        seen.update((fix_id, folder))
        path = base / folder
        if path.is_symlink() or not path.is_dir() or path.resolve().parent != base.resolve():
            raise Refused(f"Fix folder is missing: {folder}")
        folder_manifest = _read_json(path / "manifest.json", f"{folder}/manifest.json")
        hashes = folder_manifest.get("files") if isinstance(folder_manifest.get("files"), dict) else {}
        for name in ("fix.json", "runner.py"):
            if not (path / name).is_file() or hashes.get(name) != _sha256(path / name):
                raise Refused(f"Package content changed: {folder}/{name}")
        config = _read_json(path / "fix.json", f"{folder}/fix.json")
        if (config.get("fix_id") != fix_id or config.get("combined_run_id") != run_id
                or (config.get("requires") or "none") != item["requires"]
                or (package.get("database") is not None and config.get("database") != package["database"])):
            raise Refused(f"{folder}/fix.json does not belong to this package")
        out.append({"fix_id": fix_id, "folder": folder, "requires": item["requires"],
                    "client_impact": item["client_impact"], "config": config,
                    "restart_round": item.get("restart_round", 1) if item["requires"] == "restart" else None})
    target_id = package.get("target_id") or out[0]["config"].get("target_id")
    return {"run_id": run_id, "target_id": target_id, "database": package.get("database"), "fixes": out}


# ---------------------------------------------------------------------------
# The local record of what this package applied
# ---------------------------------------------------------------------------

def load_state(base, package):
    path = Path(base) / STATE_FILE
    if not path.exists():
        return {"schema_version": STATE_SCHEMA, "run_id": package["run_id"], "applied": [], "rolled_back": [],
                "failed": None}
    state = _read_json(path, STATE_FILE)
    applied, known = state.get("applied"), [f["fix_id"] for f in package["fixes"]]
    if (state.get("schema_version") != STATE_SCHEMA or state.get("run_id") != package["run_id"]
            or not isinstance(applied, list) or not isinstance(state.get("rolled_back", []), list)
            or not all(isinstance(e, dict) and e.get("status") in STATUSES for e in applied)
            or [e.get("fix_id") for e in applied] != known[:len(applied)]):
        raise Refused(f"{STATE_FILE} does not match this package; nothing was run. Check the database with "
                      "each fix's own harden.sh status before removing that file")
    state.setdefault("rolled_back", [])
    state.setdefault("failed", None)
    return state


def save_state(base, state):
    state["updated_at"] = _now()
    path = Path(base) / STATE_FILE
    tmp = str(path) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, json.dumps(state, indent=2).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class _Lock:
    """One package command at a time in this folder."""

    def __init__(self, base):
        self.path, self.handle = Path(base) / LOCK_FILE, None

    def __enter__(self):
        try:
            self.handle = open(self.path, "w")
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if self.handle:
                self.handle.close()
            raise Refused("Another package command is running in this folder, or the folder is not writable") from None
        return self

    def __exit__(self, *_):
        try:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
        finally:
            self.handle.close()


# ---------------------------------------------------------------------------
# Running one fix's own runner
# ---------------------------------------------------------------------------

ENV_CONNECTION = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGDATABASE")


def _dsn_secrets(dsn):
    try:
        te = _evidence_module()
        return te.secret_values(te.parse_dsn(dsn))
    except Exception:
        return None


def safe_message(text, dsn):
    """The runner's last error line, or fixed text when it could hold a connection value."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return "The fix runner gave no reason."
    line = lines[-1]
    secrets = _dsn_secrets(dsn)
    if secrets is None or not SAFE_MESSAGE.fullmatch(line) or (dsn and dsn in line):
        return WITHHELD
    # Review finding 3: libpq can take the host, port and user from the PG* environment
    # instead of DBGUARD_DSN, and its connection errors name them.
    if "connection to server" in line.lower() or any(
            value and value in line for value in (os.environ.get(name) for name in ENV_CONNECTION)):
        return WITHHELD
    try:
        if _evidence_module().contains_secret(line, secrets):
            return WITHHELD
    except Exception:
        return WITHHELD
    return line


def run_fix(base, fix, action, *, dsn, allow_demo=False, ack=False, evidence_dir=None):
    """Run ``<folder>/runner.py <action> <fix_id>``; {ok, result, message}. Never a shell."""
    argv = [sys.executable, str(Path(base) / fix["folder"] / "runner.py"), action, fix["fix_id"],
            "--evidence-dir", str(Path(evidence_dir) / "runner")]
    if action == "apply" and ack:
        argv.append("--ack-prerequisites")
    if allow_demo:
        argv.append("--allow-demo")
    try:
        done = subprocess.run(argv, cwd=str(base), capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=RUNNER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"ok": False, "result": None,
                "message": "The fix runner did not finish in time. Inspect the database before any retry."}
    except OSError:
        return {"ok": False, "result": None, "message": "The fix runner could not be started."}
    result = None
    for line in reversed((done.stdout or "").splitlines()):
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            result = parsed
            break
    if done.returncode == 0 and result is not None:
        return {"ok": True, "result": result, "message": ""}
    return {"ok": False, "result": None, "message": safe_message(done.stderr, dsn)}


# ---------------------------------------------------------------------------
# Pictures (never change a result)
# ---------------------------------------------------------------------------

def take_picture(ctx, stage, step):
    try:
        te = _evidence_module()
        targets = te.targets_from_configs([f["config"] for f in ctx["package"]["fixes"]])
        shot = te.capture(stage, dsn=ctx["dsn"], run_id=ctx["package"]["run_id"],
                          target_id=ctx["package"]["target_id"], targets=targets, mode=ctx["screenshots"])
        archive = te.record_stage(ctx["evidence_dir"], shot, step)
        label = te.STAGES[stage]
        if shot.get("status") == "CAPTURED":
            print(f"Picture {label}: {shot['mode']} picture saved as {stage}.png."
                  + (f" {shot['reason']}" if shot.get("reason") else ""))
        else:
            print(f"Picture {label}: none. {shot.get('reason') or 'No reason recorded.'}")
        if archive:
            print(f"Evidence for upload: {archive}")
        return True
    except Exception:
        print(f"Picture ({stage}): none. Evidence capture failed; the result of this command is unchanged.")
        return False


def finish_picture(ctx, stage, step):
    try:
        _evidence_module().finish_stage(ctx["evidence_dir"], ctx["package"]["run_id"], stage, step)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _run(ctx, fix, action):
    return ctx["run_fix"](ctx["base"], fix, action, dsn=ctx["dsn"], allow_demo=ctx["allow_demo"],
                          ack=ctx.get("ack", False), evidence_dir=ctx["evidence_dir"])


def _by_id(ctx):
    return {f["fix_id"]: f for f in ctx["package"]["fixes"]}


def _touched(fix):
    """The server settings a fix changes, from its own checked fix.json (objects: none)."""
    config = fix.get("config") or {}
    names = set()
    for key in ("settings", "names"):
        if isinstance(config.get(key), list):
            names |= {n for n in config[key] if isinstance(n, str)}
    if isinstance(config.get("setting"), str):
        names.add(config["setting"])
    return names


def _names(entries):
    return ", ".join(e["fix_id"] for e in entries) or "none"


def cmd_status(ctx, args):
    state, fixes, failed = ctx["state"], ctx["package"]["fixes"], False
    recorded = {e["fix_id"]: e for e in state["applied"]}
    print(f"Package run {ctx['package']['run_id']}: {len(fixes)} fix(es), in apply order.")
    for index, fix in enumerate(fixes, 1):
        outcome = _run(ctx, fix, "status")
        if not outcome["ok"]:
            failed = True
            live = "unknown (" + outcome["message"] + ")"
        elif outcome["result"].get("matches_applied") is True:
            live = "applied"
        elif outcome["result"].get("matches_prior") is True:
            live = "not applied"
        elif index - 1 > len(state["applied"]):
            # Its tested "before" state is the one the fixes ahead of it leave, so it can only
            # be checked once they are applied (fix of 16 Nov: no false drift on a fresh target).
            live = "not applied yet (checked when the fixes before it are applied)"
        else:
            live = "drift (differs from both the tested before and after states)"
        entry = recorded.get(fix["fix_id"])
        note = ""
        if entry:
            note = {VERIFIED: f"; applied by this package at {entry.get('applied_at')}",
                    RESTART_PENDING: f"; written by this package at {entry.get('applied_at')}, active after a restart",
                    ROLLBACK_PENDING: "; rollback written, active after a restart"}[entry["status"]]
            if live.startswith("drift") and fix is not fixes[len(recorded) - 1]:
                # Each fix's "after" covers every setting it tracks; later fixes of this package
                # changed some of them, as tested. The last applied fix's check covers the
                # current state, so a real change still shows there (16 Nov).
                live = "applied (later fixes of this package changed settings it also tracks, as tested)"
        print(f"{index}. {fix['fix_id']}: {live}{note}")
    if state.get("failed"):
        print(f"Stopped part-way earlier: {state['failed'].get('fix_id')} (not recorded as applied).")
    return EXIT_FAILED if failed else EXIT_OK


def cmd_apply_all(ctx, args):
    fixes, state = ctx["package"]["fixes"], ctx["state"]
    if not args.ack_prerequisites:
        raise Refused("Review each fix's risk-review.json and check the prerequisites, then use --ack-prerequisites")
    impact = [f["fix_id"] for f in fixes if f["client_impact"]]
    if impact and not args.ack_client_impact:
        raise Refused("These fixes can block clients that are not updated: " + ", ".join(impact)
                      + ". Read CLIENT-ACTIONS.txt, prepare those clients, then use --ack-client-impact")
    if any(e["status"] == ROLLBACK_PENDING for e in state["applied"]):
        raise Refused("A rollback is waiting for a restart. " + RESTART_ROLLBACK_LINE)
    ctx["ack"] = True
    by_id = _by_id(ctx)
    written = [e for e in state["applied"] if e["status"] == RESTART_PENDING]
    if written and len(state["applied"]) < len(fixes):
        # Continuing after a restart round: the restarted fixes must be active before the
        # next round builds on them (the sandbox restarted at this same point).
        for entry in written:
            outcome = _run(ctx, by_id[entry["fix_id"]], "verify")
            if not (outcome["ok"] and outcome["result"].get("verified") is True):
                raise Refused(f"{entry['fix_id']} is written but not active yet. Restart PostgreSQL first, "
                              "then run apply-all again. (" + (outcome["message"] or "not verified") + ")")
            entry.update(status=VERIFIED, verified_at=_now())
            save_state(ctx["base"], state)
            print(f"{entry['fix_id']}: active after the restart, verified")
    pending = fixes[len(state["applied"]):]
    step = {"command": "apply-all", "result": "IN_PROGRESS", "started_at": _now(), "fixes": []}
    pictured = False
    if not state["applied"]:
        pictured = take_picture(ctx, "before", step)
    stopped, paused = None, False
    for fix in pending:
        # Each restart fix's guard expects the restart fixes before it to be ACTIVE (its tested
        # "before" state), so the package pauses for a restart after every restart fix. The
        # sandbox proved them with fewer restarts; one extra restart on the target is the safe
        # side (fix of 16 Nov). restart_round in package.json stays informational.
        if fix["requires"] == "restart" and any(e["status"] == RESTART_PENDING for e in state["applied"]):
            paused = True
            break
        print(f"Applying {fix['fix_id']} ...")
        outcome = _run(ctx, fix, "apply")
        result = outcome["result"] or {}
        if outcome["ok"] and result.get("status") == "RESTART_REQUIRED":
            status = RESTART_PENDING
        elif outcome["ok"] and result.get("verified") is True:
            status = VERIFIED
        else:
            stopped = (fix, outcome["message"] or "The fix runner did not report a verified result.")
            state["failed"] = {"fix_id": fix["fix_id"], "at": _now(), "message": stopped[1]}
            save_state(ctx["base"], state)
            step["fixes"].append({"fix_id": fix["fix_id"], "result": "FAILED"})
            break
        state["applied"].append({"fix_id": fix["fix_id"], "folder": fix["folder"], "status": status,
                                 "applied_at": _now(), "verified_at": _now() if status == VERIFIED else None})
        state["failed"] = None
        save_state(ctx["base"], state)
        step["fixes"].append({"fix_id": fix["fix_id"], "result": "RESTART_REQUIRED" if status == RESTART_PENDING else "VERIFIED"})
        print("  written; active after a restart" if status == RESTART_PENDING else "  applied and verified")
    waiting = [e for e in state["applied"] if e["status"] == RESTART_PENDING]
    step.update(result="STOPPED" if stopped else ("RESTART_REQUIRED" if waiting else "COMPLETED"), finished_at=_now())
    if pictured:
        finish_picture(ctx, "before", step)
    if stopped:
        fix, message = stopped
        print(f"STOPPED at {fix['fix_id']}: {message}")
        print(f"Already applied by this package, in order: {_names(state['applied'])}")
        print("Not run: " + (", ".join(f["fix_id"] for f in fixes[len(state["applied"]):]) or "none"))
        if waiting:
            print(f"Written but not active until PostgreSQL restarts: {_names(waiting)}")
        print("Next: sh harden.sh status. Then fix the cause and run apply-all again, or run: sh harden.sh rollback-all")
        return EXIT_FAILED
    if not pending:
        print("Every fix in this package is already recorded as applied.")
    if waiting:
        print(f"Applied by this package, in order: {_names(state['applied'])}")
        print(f"Written, active after the restart: {_names(waiting)}")
        if paused:
            print("Not applied yet (they build on these after the restart): "
                  + ", ".join(f["fix_id"] for f in fixes[len(state["applied"]):]))
            print("Use the same --screenshots and --evidence-dir options as before, if you gave any.")
            print(continue_line(args))
        else:
            print(RESTART_LINE)
        return EXIT_RESTART
    print(f"All {len(fixes)} fix(es) applied and verified.")
    print("Next: sh harden.sh verify-all")
    return EXIT_OK


def cmd_verify_all(ctx, args):
    if args.rollback:
        return _verify_rollback(ctx)
    state, fixes, by_id = ctx["state"], ctx["package"]["fixes"], _by_id(ctx)
    if any(e["status"] == ROLLBACK_PENDING for e in state["applied"]):
        raise Refused("A rollback is waiting for a restart. " + RESTART_ROLLBACK_LINE)
    if not state["applied"]:
        raise Refused("Nothing is recorded as applied by this package; run apply-all first")
    step = {"command": "verify-all", "result": "IN_PROGRESS", "started_at": _now(), "fixes": []}
    applied_ids = [e["fix_id"] for e in state["applied"]]
    for position, entry in enumerate(state["applied"]):
        # A later fix of this package changed the same settings (e.g. 3.2 pgaudit appends to the
        # preload list 5.6 passwordcheck wrote). This fix was verified when it took effect, and
        # the later fix's own check below covers the final value (fix of 16 Nov).
        later = [f for f in applied_ids[position + 1:] if _touched(by_id[f]) & _touched(by_id[entry["fix_id"]])]
        if later and entry["status"] == VERIFIED:
            step["fixes"].append({"fix_id": entry["fix_id"], "result": "VERIFIED_THEN_EXTENDED"})
            print(f"{entry['fix_id']}: verified when it took effect ({entry.get('verified_at')}); "
                  f"{', '.join(later)} then changed the same settings and is checked below")
            continue
        # Review finding 7: every other applied fix is verified again now, in a fresh
        # connection, so "verified" never relies on a check made before the restart.
        outcome = _run(ctx, by_id[entry["fix_id"]], "verify")
        if not (outcome["ok"] and outcome["result"].get("verified") is True):
            message = outcome["message"] or "The fix runner did not report a verified result."
            step["fixes"].append({"fix_id": entry["fix_id"], "result": "FAILED"})
            print(f"STOPPED at {entry['fix_id']}: not verified: {message}")
            print("If PostgreSQL has not been restarted since apply-all, restart it and run verify-all again.")
            print("No after picture: verification did not pass.")
            return EXIT_FAILED
        entry.update(status=VERIFIED, verified_at=_now())
        save_state(ctx["base"], state)
        step["fixes"].append({"fix_id": entry["fix_id"], "result": "VERIFIED"})
        print(f"{entry['fix_id']}: verified now in a fresh connection")
    partial = len(state["applied"]) < len(fixes)
    step.update(result="PARTIAL" if partial else "VERIFIED", finished_at=_now(),
                applied=len(state["applied"]), package_fixes=len(fixes))
    take_picture(ctx, "after", step)
    if partial:
        print(f"{len(state['applied'])} of {len(fixes)} fix(es) are applied and verified; the rest were not run.")
    else:
        print(f"All {len(fixes)} fix(es) verified.")
    return EXIT_OK


def _rolled_back(ctx, entry):
    state = ctx["state"]
    state["applied"].remove(entry)
    state["rolled_back"].append({"fix_id": entry["fix_id"], "applied_at": entry.get("applied_at"),
                                 "rolled_back_at": _now()})
    save_state(ctx["base"], state)


def _all_undone(ctx, step):
    step.update(result="ROLLED_BACK", finished_at=_now())
    take_picture(ctx, "rollback", step)
    print("Every fix this package applied has been rolled back and verified.")
    if ctx["state"].get("failed"):
        print(f"Note: {ctx['state']['failed'].get('fix_id')} stopped part-way during apply-all and was never "
              "recorded as applied, so it was not rolled back. Check it with: sh harden.sh status")
    return EXIT_OK


def cmd_rollback_all(ctx, args):
    state, by_id = ctx["state"], _by_id(ctx)
    if any(e["status"] == ROLLBACK_PENDING for e in state["applied"]):
        raise Refused("A rollback is waiting for a restart. " + RESTART_ROLLBACK_LINE)
    if not state["applied"]:
        raise Refused("Nothing is recorded as applied by this package; nothing was rolled back")
    step = {"command": "rollback-all", "result": "IN_PROGRESS", "started_at": _now(), "fixes": []}
    for entry in list(reversed(state["applied"])):
        print(f"Rolling back {entry['fix_id']} ...")
        outcome = _run(ctx, by_id[entry["fix_id"]], "rollback")
        result = outcome["result"] or {}
        if outcome["ok"] and result.get("status") == "RESTART_REQUIRED":
            entry.update(status=ROLLBACK_PENDING, rollback_started_at=_now())
            save_state(ctx["base"], state)
            still = [e for e in state["applied"] if e is not entry]
            print(f"  rollback written; active after a restart. Still applied: {_names(still)}")
            # One restart-required rollback at a time: the next fix's own guard compares the
            # server with the state its test recorded, so the restart has to come first.
            print(RESTART_ROLLBACK_LINE)
            return EXIT_RESTART
        if not (outcome["ok"] and result.get("verified") is True):
            message = outcome["message"] or "The fix runner did not report a verified result."
            print(f"STOPPED at {entry['fix_id']}: not rolled back: {message}")
            print(f"Still applied by this package, in order: {_names(state['applied'])}")
            print("Next: sh harden.sh status. Inspect the database before any retry.")
            return EXIT_FAILED
        _rolled_back(ctx, entry)
        step["fixes"].append({"fix_id": entry["fix_id"], "result": "ROLLED_BACK"})
        print("  rolled back and verified")
    return _all_undone(ctx, step)


def _verify_rollback(ctx):
    state, by_id = ctx["state"], _by_id(ctx)
    waiting = [e for e in state["applied"] if e["status"] == ROLLBACK_PENDING]
    if not waiting:
        raise Refused("No rollback is waiting for a restart")
    step = {"command": "verify-all --rollback", "result": "IN_PROGRESS", "started_at": _now(), "fixes": []}
    for entry in reversed(waiting):
        outcome = _run(ctx, by_id[entry["fix_id"]], "verify-rollback")
        if not (outcome["ok"] and outcome["result"].get("verified") is True):
            message = outcome["message"] or "The fix runner did not report a verified result."
            print(f"STOPPED at {entry['fix_id']}: rollback not verified: {message}")
            print("If PostgreSQL has not been restarted since rollback-all, restart it and run this again.")
            return EXIT_FAILED
        _rolled_back(ctx, entry)
        step["fixes"].append({"fix_id": entry["fix_id"], "result": "ROLLED_BACK"})
        print(f"{entry['fix_id']}: rollback verified after the restart")
    if state["applied"]:
        print(f"Still applied by this package, in order: {_names(state['applied'])}")
        print("Next: sh harden.sh rollback-all")
        return EXIT_OK
    return _all_undone(ctx, step)


COMMANDS = {"status": cmd_status, "apply-all": cmd_apply_all, "verify-all": cmd_verify_all,
            "rollback-all": cmd_rollback_all}


def build_parser():
    parser = argparse.ArgumentParser(prog="harden.sh", description="Apply, verify or roll back every fix in this package.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        command = sub.add_parser(name)
        command.add_argument("--allow-demo", action="store_true",
                             help="demo packages only, and only on a disposable database")
        command.add_argument("--screenshots", choices=("terminal", "rendered", "off"), default="terminal",
                             help="terminal (VHS; single-user machines only), rendered or off")
        command.add_argument("--evidence-dir", default=None,
                             help="where pictures and the upload zip go (default: target-evidence in this folder)")
        if name == "apply-all":
            command.add_argument("--ack-prerequisites", action="store_true")
            command.add_argument("--ack-client-impact", action="store_true")
        if name == "verify-all":
            command.add_argument("--rollback", action="store_true",
                                 help="verify a rollback that needed a restart")
    return parser


def main(argv=None, base=None, runner=None):
    base = Path(base) if base else Path(__file__).resolve().parent
    args = build_parser().parse_args(argv)
    try:
        package = load_package(base)
        dsn = os.environ.get("DBGUARD_DSN")
        if not dsn:
            raise Refused("Set DBGUARD_DSN for the reviewed target; credentials are never in the package")
        evidence_dir = (Path(args.evidence_dir) if args.evidence_dir else base / "target-evidence").absolute()
        try:
            evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            raise Refused("The evidence folder cannot be created") from None
        with _Lock(base):
            ctx = {"base": base, "package": package, "dsn": dsn, "allow_demo": args.allow_demo,
                   "screenshots": args.screenshots, "evidence_dir": evidence_dir,
                   "state": load_state(base, package), "run_fix": runner or run_fix}
            return COMMANDS[args.command](ctx, args)
    except Refused as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_REFUSED
    except Exception:
        # Never echo an unexpected error: it could hold connection details.
        print("The package command failed unexpectedly. Nothing further was run. Check the database with: "
              "sh harden.sh status", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
