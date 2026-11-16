"""Terminal pictures on the DBA's own database (bundle_assets/terminal_evidence.py), with
fakes: no database, no VHS. Covers what must never be typed or shown, the private
connection files and their cleanup, fallback reasons and the evidence zip."""
import base64
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

from services.sandbox_poc import terminal_capture as tc
from services.sandbox_poc.bundle_assets import terminal_evidence as te
from services.sandbox_poc.bundle_assets import visual_evidence

RUN_ID = "0f0e0d0c-0b0a-4908-8706-050403020100"
DSN = "host=db.internal.example port=6543 user=dba_admin password=s3cr3t-Pw dbname=appdb sslmode=require"
PNG = b"\x89PNG\r\n\x1a\n" + b"terminal-picture"
RENDERED_PNG = b"\x89PNG\r\n\x1a\n" + b"rendered-picture"
SETTINGS = {"settings": ["log_connections", "log_disconnections"], "objects": []}


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class FakeCursor:
    def __init__(self, db):
        self.db, self.description, self.rows = db, None, []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self.db.executed.append((sql, params))
        columns, rows = self.db.answer(sql, params)
        self.description, self.rows = [(c,) for c in columns], rows

    def fetchone(self):
        return self.rows[0]

    def fetchall(self):
        return list(self.rows)


class FakeConn:
    def __init__(self, db):
        self.db, self.autocommit, self.closed = db, False, False
        self.info = type("Info", (), {"password": db.password})()

    def cursor(self):
        return FakeCursor(self.db)

    def get_dsn_parameters(self):
        return dict(self.db.effective)

    def close(self):
        self.closed = True


class FakeDb:
    """Answers the fixed evidence queries; anything else is a test failure."""

    def __init__(self, dsn=DSN, show="on", owner="app_owner", undefined=(), effective=None):
        params = te.parse_dsn(dsn)
        self.password = params.pop("password", None)
        self.effective = params if effective is None else effective
        self.show, self.owner, self.undefined = show, owner, set(undefined)
        self.executed, self.connections, self.dsns = [], [], []

    def connect(self, dsn):
        self.dsns.append(dsn)
        self.connections.append(FakeConn(self))
        return self.connections[-1]

    def answer(self, sql, params):
        if sql.startswith("SET "):
            return [], []
        if sql == "SELECT pg_catalog.current_database()":
            return ["current_database"], [("appdb",)]
        if "pg_control_system" in sql:
            return ["system_identifier"], [("7300000000000000001",)]
        if sql.endswith("IS NOT NULL"):
            return ["?column?"], [(params[0] not in self.undefined,)]
        if sql.startswith("SELECT pg_catalog.current_database() AS database"):
            return ["database", "server_version", "run_id"], [("appdb", "PostgreSQL 17.2 on x86_64", RUN_ID)]
        if sql.startswith("SHOW "):
            return [sql[5:-1]], [(self.show,)]
        if sql.startswith("SELECT pg_catalog.current_setting('"):
            return ["setting"], [(None,)]
        if "FROM pg_catalog.pg_settings WHERE name IN" in sql:
            return ["name", "setting", "source"], [("log_connections", self.show, "configuration file")]
        if "pg_catalog.pg_proc" in sql:
            return ["schema_name", "function_name", "prosecdef", "proacl"], [("public", "f", True, ["=X/" + self.owner])]
        if "pg_catalog.pg_class" in sql:  # before pg_roles: the grantee form has a pg_roles sub-select
            return ["schema_name", "table_name", "grantee", "privilege_type"], [("public", "t", self.owner, "INSERT")]
        if "FROM pg_catalog.pg_roles WHERE rolname" in sql:
            return ["rolname", "rolsuper"], [("app_role", False)]
        raise AssertionError("unexpected query: " + sql)


@pytest.fixture
def rig(monkeypatch):
    """Tools present, a fake recorder that snapshots the private folder, a fake rendered
    capture, and a temp root whose path names no user."""
    root = tempfile.mkdtemp(prefix="dbgtest-")
    if not te._anonymous(root):
        shutil.rmtree(root, ignore_errors=True)
        pytest.skip("the system temp folder path shows a user name on this machine")

    class Rig:
        records, rendered, record_error, render_error = [], [], None, None

    rig = Rig()
    rig.root, rig.records, rig.rendered = root, [], []

    def fake_record(vhs, workdir, env):
        snap = {"vhs": vhs, "workdir": workdir, "dir_mode": mode_of(workdir), "env": dict(env), "files": {}}
        for name in os.listdir(workdir):
            path = os.path.join(workdir, name)
            if os.path.isfile(path):
                snap["files"][name] = (mode_of(path), Path(path).read_text())
        rig.records.append(snap)
        if rig.record_error:
            raise rig.record_error
        return PNG

    def fake_render(evidence):
        rig.rendered.append(evidence)
        if rig.render_error:
            raise rig.render_error
        return {"status": "CAPTURED", "png_base64": base64.b64encode(RENDERED_PNG).decode(),
                "sha256": hashlib.sha256(RENDERED_PNG).hexdigest()}

    real_which = shutil.which
    monkeypatch.setattr(te, "_temp_root", lambda: root)
    monkeypatch.setattr(te, "psql_path", lambda: "/usr/bin/psql")
    monkeypatch.setattr(te, "_version", lambda path, flag: "tool 1.0" if path else None)
    monkeypatch.setattr(te, "_browser_version", lambda path: "Chromium 1.0")
    monkeypatch.setattr(te, "terminal_browser", lambda: {"source": "system", "executable": "/usr/bin/chromium", "revisions": []})
    monkeypatch.setattr(te.shutil, "which", lambda name, *a, **k: f"/opt/tools/bin/{name}"
                        if name in ("vhs", "ttyd", "ffmpeg") else real_which(name, *a, **k))
    monkeypatch.setattr(te, "_record", fake_record)
    monkeypatch.setattr(visual_evidence, "capture", fake_render)
    yield rig
    shutil.rmtree(root, ignore_errors=True)


def take(rig, stage="before", dsn=DSN, targets=SETTINGS, mode="terminal", db=None, target_id="target-01"):
    db = db or FakeDb(dsn)
    rig.db = db
    return te.capture(stage, dsn=dsn, run_id=RUN_ID, target_id=target_id, targets=targets, mode=mode,
                      connect=db.connect)


def visible(rig, shot):
    """Everything a person or the upload can see: tape, typed line, SQL file, picture metadata,
    the shot record and the rendered evidence. The two private connection files are excluded."""
    parts = [json.dumps({k: v for k, v in shot.items() if k != "png"}, default=str, ensure_ascii=False),
             json.dumps(rig.rendered, default=str, ensure_ascii=False)]
    for snap in rig.records:
        parts.append(snap["workdir"])
        parts += [text for name, (_, text) in snap["files"].items() if name not in ("pg_service.conf", ".pgpass")]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# The terminal path: one fixed typed command, private files, full cleanup
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stage,label", [("before", "BEFORE"), ("after", "AFTER FIX"), ("rollback", "AFTER ROLLBACK")])
def test_terminal_stage_types_exactly_one_fixed_command(rig, stage, label):
    shot = take(rig, stage)
    assert shot["status"] == "CAPTURED" and shot["mode"] == "terminal" and shot["png"] == PNG
    assert shot["sha256"] == hashlib.sha256(PNG).hexdigest() and shot["stage_label"] == label
    snap = rig.records[0]
    typed = f"/usr/bin/psql service=dbguard -X -e -v ON_ERROR_STOP=1 -f {snap['workdir']}/dbguard-{stage}.sql"
    assert shot["typed_command"] == typed
    assert te.TYPED_ALLOWED.fullmatch(typed)
    tape = snap["files"]["stage.tape"][1]
    assert tape == te.TAPE_TEMPLATE.format(width=1400, height=1100, typed=typed, sentinel=te.SENTINEL_SHOWN)
    assert [line for line in tape.splitlines() if line.startswith("Type ")][2] == f'Type "{typed}"'
    assert tape.index("Hide") < tape.index("Show") < tape.index(typed)
    assert rig.rendered == []
    assert shot["database"] == "appdb" and shot["system_identifier"] == "7300000000000000001"


def test_private_folder_and_files_are_owner_only_and_hold_no_password_in_the_service_file(rig):
    take(rig)
    snap = rig.records[0]
    assert os.path.dirname(snap["workdir"]) == rig.root
    assert snap["dir_mode"] == 0o700
    assert set(snap["files"]) == {"pg_service.conf", ".pgpass", "dbguard-before.sql", "stage.tape"}
    for name in ("pg_service.conf", ".pgpass", "dbguard-before.sql"):
        assert snap["files"][name][0] == 0o600, name
    service = snap["files"]["pg_service.conf"][1]
    assert service.splitlines()[0] == "[dbguard]"
    assert set(service.splitlines()[1:]) == {"host=db.internal.example", "port=6543", "user=dba_admin",
                                             "dbname=appdb", "sslmode=require"}
    assert "password" not in service and "s3cr3t-Pw" not in service
    assert snap["files"][".pgpass"][1] == "*:*:*:*:s3cr3t-Pw\n"


def test_connection_files_reach_psql_only_through_the_vhs_environment(rig):
    shot = take(rig)
    snap = rig.records[0]
    assert set(snap["env"]) == {"PATH", "HOME", "TMPDIR", "PGSERVICEFILE", "PGPASSFILE"}
    assert snap["env"]["PGSERVICEFILE"] == snap["workdir"] + "/pg_service.conf"
    assert snap["env"]["PGPASSFILE"] == snap["workdir"] + "/.pgpass"
    assert snap["env"]["HOME"] == snap["workdir"] + "/home" and snap["env"]["TMPDIR"] == snap["workdir"]
    assert snap["env"]["PATH"] == "/opt/tools/bin:/usr/bin:/bin"
    tape = snap["files"]["stage.tape"][1]
    for never in ("PGSERVICEFILE", "PGPASSFILE", "pg_service.conf", ".pgpass", "db.internal.example",
                  "dba_admin", "s3cr3t-Pw", "6543"):
        assert never not in tape and never not in shot["typed_command"]


def test_the_private_folder_is_deleted_after_success(rig):
    take(rig)
    assert not os.path.exists(rig.records[0]["workdir"])
    assert os.listdir(rig.root) == []


@pytest.mark.parametrize("error", [te.CaptureRefused("VHS did not finish within 60 seconds"),
                                   te.CaptureRefused("VHS failed: the evidence query did not finish"),
                                   RuntimeError("boom s3cr3t-Pw"), KeyboardInterrupt()])
def test_the_private_folder_is_deleted_after_failure_and_timeout(rig, error):
    rig.record_error = error
    if isinstance(error, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            take(rig)
    else:
        shot = take(rig)
        assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered"
        assert "boom" not in json.dumps({k: v for k, v in shot.items() if k != "png"})
    assert set(rig.records[0]["files"]) >= {"pg_service.conf", ".pgpass"}  # they existed during the recording
    assert not os.path.exists(rig.records[0]["workdir"])
    assert os.listdir(rig.root) == []


def test_a_failure_while_writing_the_files_still_deletes_the_folder(rig, monkeypatch):
    real = te._write_private
    written = []

    def failing(path, text):
        if path.endswith(".sql"):
            raise OSError("disk full")
        written.append(path)
        real(path, text)

    monkeypatch.setattr(te, "_write_private", failing)
    shot = take(rig)
    assert len(written) == 2 and shot["mode"] == "rendered" and rig.records == []
    assert not any(os.path.exists(p) for p in written) and os.listdir(rig.root) == []


def fake_tool(folder, name, body):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def real_recorder(rig, monkeypatch, tmp_path):
    """The real _record (process start, timeout, kill, reap) around a stand-in vhs program."""
    monkeypatch.undo()
    tools = tmp_path / "tools"
    for name in ("ttyd", "ffmpeg"):
        fake_tool(tools, name, "")
    monkeypatch.setattr(te, "_temp_root", lambda: rig.root)
    monkeypatch.setattr(te, "psql_path", lambda: "/usr/bin/psql")
    monkeypatch.setattr(te, "_version", lambda path, flag: "tool 1.0" if path else None)
    monkeypatch.setattr(te, "_browser_version", lambda path: "Chromium 1.0")
    monkeypatch.setattr(te, "terminal_browser", lambda: {"source": "system", "executable": "/usr/bin/chromium", "revisions": []})
    monkeypatch.setattr(te.shutil, "which", lambda name, *a, **k: str(tools / name))
    monkeypatch.setattr(visual_evidence, "capture", lambda evidence: rig.rendered.append(evidence) or {
        "png_base64": base64.b64encode(RENDERED_PNG).decode(), "sha256": hashlib.sha256(RENDERED_PNG).hexdigest()})
    rig.tools, rig.seen = tools, tmp_path / "seen.json"
    return rig


SUCCESS_VHS = '''import json, os, stat, sys
service = os.environ["PGSERVICEFILE"]
json.dump({"env": dict(os.environ), "argv": sys.argv[1:], "cwd": os.getcwd(),
           "service_mode": stat.S_IMODE(os.stat(service).st_mode), "service": open(service).read(),
           "pgpass_mode": stat.S_IMODE(os.stat(os.environ["PGPASSFILE"]).st_mode),
           "home_mode": stat.S_IMODE(os.stat(os.environ["HOME"]).st_mode)}, open(SEEN, "w"))
open("shot.png", "wb").write(PNG)'''


def test_real_recorder_gives_vhs_a_minimal_environment_and_cleans_up(real_recorder):
    rig = real_recorder
    fake_tool(rig.tools, "vhs", f"SEEN, PNG = {str(rig.seen)!r}, {PNG!r}\n" + SUCCESS_VHS)
    shot = take(rig)
    assert shot["status"] == "CAPTURED" and shot["mode"] == "terminal" and shot["png"] == PNG
    seen = json.loads(rig.seen.read_text())
    assert set(seen["env"]) - {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"} == {"PATH", "HOME", "TMPDIR", "PGSERVICEFILE", "PGPASSFILE"}
    assert seen["argv"] == ["stage.tape"]
    assert seen["service_mode"] == 0o600 and seen["pgpass_mode"] == 0o600 and seen["home_mode"] == 0o500
    assert "password" not in seen["service"]
    assert not os.path.exists(seen["cwd"]) and os.listdir(rig.root) == []
    assert "DBGUARD_DSN" not in seen["env"] and DSN not in json.dumps(seen["env"])


def test_real_recorder_timeout_kills_vhs_and_deletes_the_private_files(real_recorder, monkeypatch):
    rig = real_recorder
    pid_file = rig.seen
    fake_tool(rig.tools, "vhs", f"import os, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\ntime.sleep(120)")
    monkeypatch.setattr(te, "VHS_TIMEOUT_SECONDS", 1)
    shot = take(rig)
    assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered"
    assert "VHS did not finish within 1 seconds" in shot["reason"]
    assert os.listdir(rig.root) == []
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)  # the stand-in vhs was killed and reaped


def test_real_recorder_vhs_failure_falls_back_and_cleans_up(real_recorder):
    rig = real_recorder
    fake_tool(rig.tools, "vhs", "import sys\nsys.exit(1)")
    shot = take(rig)
    assert shot["mode"] == "rendered" and "VHS failed" in shot["reason"]
    assert os.listdir(rig.root) == []


def test_real_recorder_refuses_something_that_is_not_a_png(real_recorder):
    rig = real_recorder
    fake_tool(rig.tools, "vhs", "open('shot.png', 'w').write('<html>')")
    shot = take(rig)
    assert shot["mode"] == "rendered" and "not a PNG" in shot["reason"]
    assert os.listdir(rig.root) == []


def test_no_password_means_no_pgpass_file_but_the_private_path_is_still_used(rig):
    take(rig, dsn="host=db.internal.example user=dba_admin dbname=appdb")
    snap = rig.records[0]
    assert ".pgpass" not in snap["files"]
    assert snap["env"]["PGPASSFILE"] == snap["workdir"] + "/.pgpass"  # never the DBA's own ~/.pgpass


def test_values_libpq_resolved_itself_are_used_and_masked(rig):
    """host/user from PG* environment variables are not in DBGUARD_DSN; the effective values
    of the live connection are written to the service file and treated as connection values."""
    db = FakeDb("dbname=appdb", effective={"dbname": "appdb", "host": "resolved.example", "port": "5433",
                                           "user": "env_user", "sslmode": "prefer", "krbsrvname": "postgres"})
    db.password = "from-pgpass"
    shot = take(rig, dsn="dbname=appdb", db=db)
    service = rig.records[0]["files"]["pg_service.conf"][1]
    assert set(service.splitlines()[1:]) == {"dbname=appdb", "host=resolved.example", "port=5433",
                                             "user=env_user", "sslmode=prefer"}
    assert rig.records[0]["files"][".pgpass"][1] == "*:*:*:*:from-pgpass\n"
    for value in ("resolved.example", "env_user", "from-pgpass"):
        assert value not in visible(rig, shot)
    db.owner = "env_user"  # now the output shows the connecting user
    again = take(rig, dsn="dbname=appdb", db=db, targets={"settings": [], "objects": [
        {"kind": "table", "target": {"schema": "public", "table": "t", "grantee": "app_role"}}]})
    assert again["mode"] == "rendered" and "env_user" not in visible(rig, again)


# ---------------------------------------------------------------------------
# Hostile connection values never reach the tape, typed line, SQL, metadata or files
# ---------------------------------------------------------------------------

HOSTILE = {
    "shell": ("host='evil-host;$(id)' port=6543 user='ro\"ot $(whoami)' password='p:a\\\\ss;`x`' dbname=appdb",
              ["evil-host", "$(id)", "whoami", 'ro"ot', "p:a", "`x`"]),
    "quotes_spaces": ("host='ho st\\'s' port=6543 user='us er\\'; DROP' password='pa ss\\' OR 1=1 --' dbname=appdb",
                      ["ho st", "us er", "DROP", "pa ss", "OR 1=1"]),
    "newline_password": ("host=evilhost port=6543 user=eviluser password='line1\nEVIL-LINE2' dbname=appdb",
                         ["evilhost", "eviluser", "line1", "EVIL-LINE2"]),
    "newline_host": ("host='evilhost\nType \"rm -rf\"' port=6543 user=eviluser password=evilpass dbname=appdb",
                     ["evilhost", "rm -rf", "eviluser", "evilpass"]),
    "uri": ("postgresql://evil%24%28id%29user:p%40ss%3Bw%60rd@evil-uri-host:6543/appdb?sslmode=require",
            ["evil$(id)user", "p@ss;w`rd", "evil-uri-host", "%24%28id%29"]),
}


@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_hostile_dsn_values_never_reach_the_tape_typed_line_sql_or_metadata(rig, case, tmp_path):
    dsn, values = HOSTILE[case]
    shot = take(rig, dsn=dsn)
    assert shot["status"] == "CAPTURED"
    te.record_stage(tmp_path / "ev", shot, {"command": "apply-all", "result": "COMPLETED"})
    text = visible(rig, shot)
    for path in (tmp_path / "ev").iterdir():
        if path.suffix == ".json":
            text += path.read_text()
    with zipfile.ZipFile(tmp_path / "ev" / f"target-evidence-{RUN_ID}.zip") as archive:
        text += "".join(archive.read(n).decode("latin-1") for n in archive.namelist())
    for value in values:
        assert value not in text, value
    if shot["mode"] == "terminal":
        assert te.TYPED_ALLOWED.fullmatch(shot["typed_command"])
        te.check_tape(rig.records[0]["files"]["stage.tape"][1], shot["typed_command"])
    assert os.listdir(rig.root) == []


def test_values_that_fit_one_line_still_get_a_terminal_picture_and_escaped_pgpass(rig):
    shot = take(rig, dsn=HOSTILE["shell"][0])
    assert shot["mode"] == "terminal"
    files = rig.records[0]["files"]
    assert files[".pgpass"][1] == "*:*:*:*:p\\:a\\\\ss;`x`\n"  # backslash and colon escaped
    assert "host=evil-host;$(id)" in files["pg_service.conf"][1].splitlines()


@pytest.mark.parametrize("case,reason", [("newline_password", "password cannot be written"),
                                         ("newline_host", "cannot be written to a private service file")])
def test_values_with_a_newline_are_never_written_and_fall_back(rig, case, reason):
    shot = take(rig, dsn=HOSTILE[case][0])
    assert shot["mode"] == "rendered" and reason in shot["reason"]
    assert rig.records == [] and os.listdir(rig.root) == []


def test_typed_line_is_built_only_from_the_allowlist(rig, monkeypatch):
    folder = te.private_dir()
    try:
        line = te.typed_command("/usr/bin/psql", folder, "after", {})
        assert line == f"/usr/bin/psql service=dbguard -X -e -v ON_ERROR_STOP=1 -f {folder}/dbguard-after.sql"
        with pytest.raises(te.CaptureRefused):
            te.typed_command(str(Path.home() / "bin" / "psql"), folder, "after", {})
        with pytest.raises(te.CaptureRefused):
            te.typed_command("/usr/bin/psql -h evil", folder, "after", {})
        with pytest.raises(te.CaptureRefused):
            te.typed_command("/usr/bin/psql", folder, "during", {})
        with pytest.raises(te.CaptureRefused):
            te.typed_command("/usr/bin/psql", folder + "/a b", "after", {})
        with pytest.raises(te.CaptureRefused):
            te.typed_command("/usr/bin/psql", folder + "/$(id)", "after", {})
        with pytest.raises(te.CaptureRefused):  # the folder path itself shows a connection value
            te.typed_command("/usr/bin/psql", folder, "after", {os.path.basename(folder): False})
    finally:
        te._remove(folder)
    for path in ("/usr/bin/psql", "/usr/local/bin/psql", "/opt/homebrew/bin/psql", "/usr/pgsql-17/bin/psql",
                 "/usr/lib/postgresql/17/bin/psql"):
        assert path in te.PSQL_PATHS
    assert all(te.TYPED_ALLOWED.fullmatch(p) and str(Path.home()) not in p for p in te.PSQL_PATHS)


@pytest.mark.parametrize("line", ["psql; rm -rf /", "psql $(id)", "psql `id`", "psql | sh", "psql > x", "psql\nid",
                                  "psql 'x'", 'psql "x"', "psql \\x", "psql & id", "psql\tx", "psql café", ""])
def test_check_typed_refuses_shell_characters(line):
    with pytest.raises(te.CaptureRefused):
        te.check_typed(line)


@pytest.mark.parametrize("tamper", [
    lambda t: t.replace("Hide\n", ""),
    lambda t: t.replace("Screenshot shot.png", "Screenshot /tmp/x.png"),
    lambda t: t + 'Type "id"\nEnter\n',
    lambda t: t.replace("Set Height 1100", "Set Height 1101"),
    lambda t: t.replace('Type "clear"', 'Type "env"'),
    lambda t: t.replace("bash --norc --noprofile", "bash"),
    lambda t: t.replace("service=dbguard", "service=other"),
    lambda t: t.replace("ON_ERROR_STOP=1", "ON_ERROR_STOP=1​"),
])
def test_tampered_tapes_are_refused(tamper):
    typed = "/usr/bin/psql service=dbguard -X -e -v ON_ERROR_STOP=1 -f /tmp/dbguard-pkg-x/dbguard-before.sql"
    tape = te.build_tape(typed, (1400, 1100))
    te.check_tape(tape, typed)
    with pytest.raises(te.CaptureRefused):
        te.check_tape(tamper(tape), typed)
    with pytest.raises(te.CaptureRefused):
        te.build_tape(typed, (1400, 999))


# ---------------------------------------------------------------------------
# The SQL file: read-only, fixed templates, never the address or a secret
# ---------------------------------------------------------------------------

def test_sql_file_is_read_only_fixed_templates_with_no_address(rig):
    shot = take(rig)
    sql = rig.records[0]["files"]["dbguard-before.sql"][1]
    lines = sql.splitlines()
    assert lines[0] == "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;" == tc.READ_ONLY_LINE
    assert lines[1] == "SET search_path = pg_catalog, pg_temp;"
    assert lines[2] == "SET standard_conforming_strings = on;"
    assert lines[3] == ("SELECT item, value FROM (VALUES ('run_id', '" + RUN_ID + "'), ('stage', 'BEFORE'), "
                        "('target_id', 'target-01'), ('captured_utc', '" + shot["captured_at"] + "'), "
                        "('raw_output_sha256', '" + shot["raw_output_sha256"] + "')) AS dbguard_evidence(item, value);")
    assert lines[4] == ("SELECT pg_catalog.current_database() AS database, pg_catalog.version() AS server_version, "
                        f"'{RUN_ID}' AS run_id;")
    assert lines[5:8] == ["SHOW log_connections;", "SHOW log_disconnections;",
                          "SELECT name, setting, source FROM pg_catalog.pg_settings WHERE name IN "
                          "('log_connections', 'log_disconnections') ORDER BY name;"]
    assert lines[8] == "SELECT pg_catalog.upper('end of dbguard evidence') AS status;" and len(lines) == 9
    te.check_sql(sql)
    lowered = sql.lower()
    for never in ("inet_server", "inet_client", "pg_authid", "rolpassword", "pg_shadow", "password", "current_user",
                  "session_user", "pg_stat_activity"):
        assert never not in lowered
    assert shot["raw_output_sha256"] == te.digest(shot["raw_output"])
    assert [q["query"] for q in shot["raw_output"]] == lines[4:8]


def test_the_session_that_reads_the_output_is_read_only_and_closed(rig):
    take(rig)
    statements = [sql for sql, _ in rig.db.executed]
    assert statements[:3] == [te.READ_ONLY_LINE, "SET statement_timeout = '15s'", "SET search_path = pg_catalog, pg_temp"]
    assert all(s.startswith(("SET ", "SELECT ", "SHOW ")) for s in statements)
    assert not any("inet_server" in s or "pg_authid" in s for s in statements)
    assert rig.db.connections[0].closed and rig.db.connections[0].autocommit is True


def test_an_undefined_custom_setting_is_read_without_show(rig):
    take(rig, targets={"settings": ["pgaudit.log"], "objects": []}, db=FakeDb(undefined={"pgaudit.log"}))
    sql = rig.records[0]["files"]["dbguard-before.sql"][1]
    assert "SELECT pg_catalog.current_setting('pgaudit.log', true) AS \"pgaudit.log\";" in sql
    assert "SHOW pgaudit.log" not in sql


@pytest.mark.parametrize("name", ["ssl_passphrase_command", "archive_command", "primary_conninfo", "custom.secret",
                                  "Log_Connections", "log_connections; DROP TABLE x", "x'y", "", None, 7])
def test_secret_or_malformed_setting_names_are_never_queried(rig, name):
    shot = take(rig, targets={"settings": [name], "objects": []})
    assert shot["status"] == "UNAVAILABLE" and "nothing was pictured" in shot["reason"]
    assert rig.records == [] and rig.rendered == []
    assert not any(isinstance(name, str) and name and name in sql for sql, _ in rig.db.executed)


def test_collector_redaction_lists_mirror_the_spec_engine():
    from app.services.spec_engine import redaction
    assert te.COLLECTOR_SECRET_SETTINGS == redaction.COLLECTOR_SECRET_SETTINGS
    assert te.COLLECTOR_REVIEWED_CUSTOM_SETTINGS == redaction.COLLECTOR_REVIEWED_CUSTOM_SETTINGS
    for name in ("archive_command", "ARCHIVE_COMMAND", "pgaudit.log", "PGAUDIT.LOG", "custom.thing", "log_connections",
                 "Kgaudit.log", "ssl_passphrase_command", "pg_stat_statements.max"):
        assert te.collector_redacts(name) == redaction.collector_redacts(name), name


def test_masking_patterns_mirror_the_sandbox_capture():
    assert [(p.pattern, p.flags, r) for p, r in te._MASKS] == [(p.pattern, p.flags, r) for p, r in tc._MASKS]
    for sample in ("host=a password=hunter2 x", "postgresql://u:pw@h/db", "--password=abc", "passfile=/x/y", "plain"):
        assert te.redact(sample) == tc.redact(sample)


OBJECTS = [
    {"kind": "role", "target": {"role": "app_role"}},
    {"kind": "function", "target": {"schema": "public", "name": "f", "identity_args": ""}},
    {"kind": "function", "target": {"schema": "public", "name": "f", "identity_args": "integer, text"}},
    {"kind": "table", "target": {"schema": "public", "table": "t", "grantee": "PUBLIC", "privileges": ["INSERT"]}},
    {"kind": "table", "target": {"schema": "public", "table": "t", "grantee": "app_role"}},
    {"kind": "table", "target": {"schema": "public", "table": "t"}},
]


def test_object_queries_read_one_object_from_fixed_templates(rig):
    shot = take(rig, targets={"settings": [], "objects": OBJECTS})
    assert shot["mode"] == "terminal"
    sql = rig.records[0]["files"]["dbguard-before.sql"][1]
    assert "FROM pg_catalog.pg_roles WHERE rolname = 'app_role';" in sql
    assert "pg_get_function_identity_arguments(p.oid) = '';" in sql
    assert "pg_get_function_identity_arguments(p.oid) = 'integer, text';" in sql
    assert "AND a.grantee = 0 ORDER BY" in sql
    assert "AND a.grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'app_role')" in sql
    assert "c.relrowsecurity" in sql
    for query in te.object_queries(OBJECTS[0]) + te.object_queries(OBJECTS[3]):
        assert "pg_authid" not in query[1] and "rolpassword" not in query[1]


@pytest.mark.parametrize("name", ["x'; DROP TABLE t; --", 'we"ird', "sp ace", "semi;colon", "dollar$tag$", "café"])
def test_hostile_object_names_appear_only_inside_a_quoted_literal(rig, name):
    shot = take(rig, targets={"settings": [], "objects": [{"kind": "role", "target": {"role": name}}]})
    sql = rig.records[0]["files"]["dbguard-before.sql"][1] if rig.records else shot["raw_output"][1]["query"]
    literal = "'" + name.replace("'", "''") + "'"
    assert f"WHERE rolname = {literal};" in sql
    te.check_sql(te.evidence_sql(te.stamp_query("before", RUN_ID, "t", "2026-11-11T00:00:00Z", "a" * 64),
                                 te.object_queries({"kind": "role", "target": {"role": name}})))


@pytest.mark.parametrize("name", ["back\\slash", "new\nline", "nul\x00", "rtl‮override", "zero​width", "x" * 64,
                                  "", None, 5])
def test_names_that_cannot_be_quoted_safely_are_refused(rig, name):
    for item in ({"kind": "role", "target": {"role": name}},
                 {"kind": "table", "target": {"schema": name, "table": "t"}},
                 {"kind": "function", "target": {"schema": "s", "name": name, "identity_args": ""}}):
        shot = take(rig, targets={"settings": [], "objects": [item]})
        assert shot["status"] == "UNAVAILABLE"
    assert rig.records == [] and rig.rendered == []


@pytest.mark.parametrize("item", [None, {}, {"kind": "role"}, {"kind": "view", "target": {}}, {"kind": "role", "target": []}])
def test_malformed_object_targets_are_refused(item):
    with pytest.raises(te.CaptureRefused):
        te.object_queries(item)


GOOD_SQL = te.READ_ONLY_LINE + "\nSET search_path = pg_catalog, pg_temp;\nSELECT 1;\n"


@pytest.mark.parametrize("statement", [
    "SELECT inet_server_addr();", "SELECT pg_catalog.inet_server_port();", "SELECT inet_client_addr();",
    "SELECT rolpassword FROM pg_catalog.pg_authid;", "SELECT * FROM pg_shadow;", "SELECT * FROM pg_user_mappings;",
    "SELECT pg_read_file('/etc/passwd');", "SELECT pg_ls_dir('.');", "COPY t TO '/tmp/x';",
    "SELECT lo_import('/etc/passwd');", "SELECT set_config('x', 'y', false);", "SELECT pg_reload_conf();",
    "SELECT * FROM pg_stat_activity;", "SELECT * FROM pg_hba_file_rules;", "SHOW ssl_key_file;",
    "ALTER SYSTEM SET log_connections = 'on';", "UPDATE t SET x = 1;", "DROP TABLE t;", "SET search_path = public;",
    "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE;", "SELECT 1; -- comment", "SELECT /* c */ 1;",
    "SELECT $$x$$;", "SELECT 'a' \\gexec", "SELECT U&\"d\\0061t\";", "SELECT 'unterminated;", "SELECT 1; trailing",
    "SELECT 'x'::regclass;", "SELECT query_to_xml('select 1', true, true, '');",
])
def test_check_sql_refuses_anything_outside_the_fixed_templates(statement):
    te.check_sql(GOOD_SQL)
    with pytest.raises(te.CaptureRefused):
        te.check_sql(GOOD_SQL + statement + "\n")


@pytest.mark.parametrize("sql", ["SELECT 1;\n", "SELECT 1;\n" + GOOD_SQL, GOOD_SQL.replace("READ ONLY", "READ WRITE"),
                                 GOOD_SQL + "SELECT '" + "x" * 70000 + "';\n", None, b"SELECT 1;"])
def test_check_sql_requires_the_read_only_first_line_and_a_size_limit(sql):
    with pytest.raises(te.CaptureRefused):
        te.check_sql(sql)


def test_targets_come_from_the_changed_settings_and_the_one_object():
    configs = [{"setting": "log_connections", "names": ["log_connections", "port", "ssl"]},
               {"kind": "catalog_setting", "setting": "shared_preload_libraries",
                "settings": ["shared_preload_libraries", "pgaudit.log"]},
               {"kind": "object", "prior": {"kind": "role"}, "target": {"role": "app_role"}},
               {"setting": "log_connections"}]
    assert te.targets_from_configs(configs) == {
        "settings": ["log_connections", "shared_preload_libraries", "pgaudit.log"],
        "objects": [{"kind": "role", "target": {"role": "app_role"}}]}


# ---------------------------------------------------------------------------
# Masking the output; fallback reasons; a capture problem never raises
# ---------------------------------------------------------------------------

TABLE = {"settings": [], "objects": [{"kind": "table", "target": {"schema": "public", "table": "t", "grantee": "app_role"}}]}


@pytest.mark.parametrize("owner,gone", [("dba_admin", "dba_admin"), ("x s3cr3t-Pw x", "s3cr3t-Pw"),
                                        ("DB.Internal.Example", "DB.Internal.Example"), ("port 6543", "6543")])
def test_output_showing_a_connection_value_is_masked_and_never_reaches_a_terminal(rig, owner, gone):
    shot = take(rig, targets=TABLE, db=FakeDb(owner=owner))
    assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered" and shot["redacted"] is True
    assert "a terminal cannot be masked" in shot["reason"]
    assert rig.records == [] and os.listdir(rig.root) == []  # no private folder was ever made
    assert gone not in visible(rig, shot)
    assert te.MASK in rig.rendered[0]["queries"][0]["output"] or te.MASK in json.dumps(rig.rendered)
    assert te.MASK in json.dumps(shot["raw_output"])


def test_output_matching_the_collectors_redaction_rules_is_redacted(rig):
    shot = take(rig, db=FakeDb(show="host=x password=hunter2 dbname=y"))
    assert shot["mode"] == "rendered" and "hunter2" not in visible(rig, shot)
    assert "***REDACTED***" in json.dumps(shot["raw_output"])


def test_a_query_text_showing_a_connection_value_is_never_echoed_by_psql(rig):
    targets = {"settings": [], "objects": [{"kind": "role", "target": {"role": "dba_admin"}}]}
    shot = take(rig, targets=targets)
    assert shot["mode"] == "rendered" and rig.records == []
    assert "dba_admin" not in visible(rig, shot)


def test_a_target_id_showing_a_connection_value_is_masked(rig):
    shot = take(rig, target_id="db.internal.example")
    assert shot["target_id"] == te.MASK and "db.internal.example" not in visible(rig, shot)
    odd = take(rig, target_id="<script>\x00")
    assert odd["target_id"] == "not recorded"


def no_vhs(rig, monkeypatch):
    monkeypatch.setattr(te, "_version", lambda path, flag: None if path and path.endswith("/vhs") else "tool 1.0")


def no_ffmpeg(rig, monkeypatch):
    monkeypatch.setattr(te, "_version", lambda path, flag: None if path and path.endswith("/ffmpeg") else "tool 1.0")


def no_psql(rig, monkeypatch):
    monkeypatch.setattr(te, "psql_path", lambda: None)


def no_browser(rig, monkeypatch):
    monkeypatch.setattr(te, "terminal_browser", lambda: None)


def user_name_in_temp_path(rig, monkeypatch):
    monkeypatch.setattr(te, "_user_names", lambda: {"dbgtest"})


def temp_folder_under_home(rig, monkeypatch):
    monkeypatch.setenv("HOME", os.path.dirname(rig.root))


def vhs_failed(rig, monkeypatch):
    rig.record_error = te.CaptureRefused("VHS failed: the evidence query did not finish, or the terminal or its "
                                         "browser did not start")


def unexpected_error(rig, monkeypatch):
    rig.record_error = RuntimeError("boom")


@pytest.mark.parametrize("setup,reason", [
    (no_vhs, "VHS, ttyd or ffmpeg is not installed"), (no_ffmpeg, "VHS, ttyd or ffmpeg is not installed"),
    (no_psql, "psql is not installed at a standard path"), (no_browser, "The terminal browser is not set up"),
    (user_name_in_temp_path, "shows the home folder or a user name"),
    (temp_folder_under_home, "shows the home folder or a user name"),
    (vhs_failed, "VHS failed"), (unexpected_error, "Terminal capture failed"),
])
def test_fallback_to_the_rendered_picture_records_the_reason(rig, monkeypatch, setup, reason):
    setup(rig, monkeypatch)
    shot = take(rig)
    assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered" and shot["png"] == RENDERED_PNG
    assert shot["reason"].startswith("Terminal capture UNAVAILABLE: ") and reason in shot["reason"]
    assert shot["reason"].endswith("Rendered capture of the same queries used instead.")
    assert shot["typed_command"] is None and os.listdir(rig.root) == []
    assert len(rig.rendered) == 1 and rig.rendered[0]["note"] == shot["reason"]


@pytest.mark.parametrize("dsn", ["dbname=appdb options='-c search_path=evil'", "service=prod", "dbname=appdb replication=database"])
def test_a_dsn_option_the_service_file_cannot_carry_falls_back(rig, dsn):
    shot = take(rig, dsn=dsn)
    assert shot["mode"] == "rendered" and "connection option" in shot["reason"] and rig.records == []


def test_too_much_output_for_one_picture_falls_back(rig):
    names = [f"setting_{i:03d}" for i in range(300)]
    shot = take(rig, targets={"settings": names, "objects": []})
    assert shot["mode"] == "rendered" and "Too much output" in shot["reason"]
    assert te.geometry_for("x\n" * 10, []) == (1400, 1100)
    assert te.geometry_for("x\n" * 90, []) == (1400, 2000)


def test_when_the_rendered_capture_also_fails_the_stage_is_unavailable_with_both_reasons(rig, monkeypatch):
    no_vhs(rig, monkeypatch)
    rig.render_error = RuntimeError("Evidence browser unavailable")
    shot = take(rig)
    assert shot["status"] == "UNAVAILABLE" and "png" not in shot
    assert "VHS, ttyd or ffmpeg is not installed" in shot["reason"] and "Rendered capture also failed" in shot["reason"]
    assert shot["raw_output"]  # the query output is still recorded


def test_rendered_and_off_modes_never_make_a_private_folder_or_start_vhs(rig):
    rendered = take(rig, mode="rendered")
    assert rendered["mode"] == "rendered" and rendered["status"] == "CAPTURED"
    assert rendered["reason"] == "Rendered capture chosen (--screenshots rendered)."
    off = take(rig, mode="off")
    assert off["status"] == "OFF" and "png" not in off and off["raw_output"]
    assert rig.records == [] and os.listdir(rig.root) == [] and len(rig.rendered) == 1


def test_rendered_picture_metadata_has_the_stamp_and_no_connection_details(rig):
    shot = take(rig, mode="rendered")
    evidence = rig.rendered[0]
    assert set(evidence) == {"scope", "run_id", "stage", "target_id", "captured_at", "raw_output_sha256", "note", "queries"}
    assert evidence["scope"] == "DBA TARGET · BEFORE" and evidence["run_id"] == RUN_ID
    assert evidence["raw_output_sha256"] == shot["raw_output_sha256"] and evidence["target_id"] == "target-01"
    html = visual_evidence.render_html(evidence)
    for never in ("db.internal.example", "6543", "dba_admin", "s3cr3t-Pw", "inet_server", "Server Address"):
        assert never not in html


@pytest.mark.parametrize("failure", [RuntimeError("could not connect to " + DSN), KeyError("x")])
def test_a_database_problem_is_a_reason_never_an_exception_and_never_shows_the_dsn(rig, failure):
    def refuse(dsn):
        raise failure

    shot = te.capture("before", dsn=DSN, run_id=RUN_ID, target_id="t", targets=SETTINGS, connect=refuse)
    assert shot["status"] == "UNAVAILABLE"
    assert shot["reason"] == "The evidence queries could not be run; nothing was pictured."
    assert "s3cr3t-Pw" not in json.dumps(shot) and "db.internal.example" not in json.dumps(shot)


@pytest.mark.parametrize("kwargs", [dict(stage="during"), dict(run_id="../x"), dict(run_id=None), dict(targets=None),
                                    dict(dsn="not a dsn ==="), dict(dsn=None)])
def test_capture_never_raises(rig, kwargs):
    args = dict(stage="before", dsn=DSN, run_id=RUN_ID, target_id="t", targets=SETTINGS, connect=FakeDb().connect)
    args.update(kwargs)
    stage = args.pop("stage")
    shot = te.capture(stage, **args)
    assert shot["status"] == "UNAVAILABLE" and shot["reason"]
    assert rig.records == [] and os.listdir(rig.root) == []


# ---------------------------------------------------------------------------
# The server's address is never queried or pictured, on any path
# ---------------------------------------------------------------------------

def test_the_per_fix_runner_no_longer_asks_for_the_server_address():
    source = (Path(te.__file__).parent / "runner.py").read_text()
    for never in ("inet_server_addr", "inet_server_port", "server_address", "server_port"):
        assert never not in source


def test_rendered_evidence_drops_connection_details_at_any_depth():
    evidence = {"scope": "DBA TARGET · VERIFY", "run_id": "r1", "host": "10.1.2.3", "Port": 5444,
                "database_identity": {"database": "appdb", "server_address": "10.9.8.7/32", "server_port": 5433,
                                      "server_version": "17.2", "nested": [{"inet_server_addr": "10.5.5.5"}]},
                "dsn": "postgresql://u:pw@h/db", "password": "pw-value",
                "queries": [{"title": "t", "query": "SELECT 1", "output": [[1]]}]}
    html = visual_evidence.render_html(evidence)
    for never in ("10.1.2.3", "5444", "10.9.8.7", "5433", "10.5.5.5", "pw-value", "postgresql://", "Server Address"):
        assert never not in html
    assert "appdb" in html and "17.2" in html and "r1" in html
    assert visual_evidence.without_connection_details(evidence)["database_identity"] == {
        "database": "appdb", "server_version": "17.2", "nested": [{}]}


# ---------------------------------------------------------------------------
# target-evidence-<run_id>.zip
# ---------------------------------------------------------------------------

def record_all(rig, folder):
    for stage in ("before", "after", "rollback"):
        shot = take(rig, stage)
        archive = te.record_stage(folder, shot, {"command": "x", "result": "COMPLETED"})
    return archive


def test_evidence_zip_holds_only_the_fixed_png_and_json_names_with_a_full_manifest(rig, tmp_path):
    folder = tmp_path / "ev"
    (folder / "runner" / "verification-1").mkdir(parents=True)
    (folder / "runner" / "verification-1" / "event.json").write_text("{}")
    (folder / "notes.txt").write_text("not evidence")
    (folder / "before.html").write_text("<html>")
    archive = record_all(rig, folder)
    assert archive == folder / f"target-evidence-{RUN_ID}.zip" and mode_of(archive) == 0o600
    with zipfile.ZipFile(archive) as z:
        names = set(z.namelist())
        assert names == {"before.png", "after.png", "rollback.png", "queries-before.json", "queries-after.json",
                         "queries-rollback.json", "event-before.json", "event-after.json", "event-rollback.json",
                         "manifest.json"} == set(te.zip_members())
        assert all(n.endswith((".png", ".json")) and "/" not in n for n in names)
        manifest = json.loads(z.read("manifest.json"))
        assert set(manifest["files"]) == names - {"manifest.json"}
        for name, digest in manifest["files"].items():
            assert hashlib.sha256(z.read(name)).hexdigest() == digest
        assert manifest["run_id"] == RUN_ID and manifest["database"] == "appdb"
        assert manifest["system_identifier"] == "7300000000000000001" and manifest["identity_consistent"] is True
        assert manifest["schema_version"] == "dbguard-target-evidence-v1"
        assert z.read("before.png") == PNG
        event = json.loads(z.read("event-after.json"))
        queries = json.loads(z.read("queries-after.json"))
    assert event["stage"] == "after" and event["stage_label"] == "AFTER FIX" and event["mode"] == "terminal"
    assert event["status"] == "CAPTURED" and event["png_sha256"] == hashlib.sha256(PNG).hexdigest()
    assert event["tools"] == {"vhs": "tool 1.0", "ttyd": "tool 1.0", "ffmpeg": "tool 1.0", "psql": "tool 1.0",
                              "browser": {"source": "system", "path": "/usr/bin/chromium", "version": "Chromium 1.0"}}
    assert event["typed_command"].startswith("/usr/bin/psql service=dbguard -X -e -v ON_ERROR_STOP=1 -f ")
    assert event["step"] == {"command": "x", "result": "COMPLETED"} and event["captured_at"].endswith("Z")
    assert event["raw_output_sha256"] == queries["raw_output_sha256"] == te.digest(queries["queries"])
    assert queries["run_id"] == RUN_ID and queries["stage"] == "after"


def test_a_stage_recorded_again_without_a_picture_drops_the_stale_png(rig, tmp_path, monkeypatch):
    folder = tmp_path / "ev"
    record_all(rig, folder)
    no_vhs(rig, monkeypatch)
    rig.render_error = RuntimeError("no browser")
    archive = te.record_stage(folder, take(rig, "after"), {"command": "verify-all", "result": "VERIFIED"})
    assert not (folder / "after.png").exists()
    with zipfile.ZipFile(archive) as z:
        assert "after.png" not in z.namelist() and "before.png" in z.namelist()
        event = json.loads(z.read("event-after.json"))
        assert "after.png" not in json.loads(z.read("manifest.json"))["files"]
    assert event["status"] == "UNAVAILABLE" and event["png_sha256"] is None and event["png_member"] is None


def test_finish_stage_records_the_final_result_and_refreshes_the_zip(rig, tmp_path):
    folder = tmp_path / "ev"
    te.record_stage(folder, take(rig), {"command": "apply-all", "result": "IN_PROGRESS"})
    archive = te.finish_stage(folder, RUN_ID, "before", {"command": "apply-all", "result": "STOPPED"})
    with zipfile.ZipFile(archive) as z:
        event = z.read("event-before.json")
        assert json.loads(event)["step"]["result"] == "STOPPED"
        assert json.loads(z.read("manifest.json"))["files"]["event-before.json"] == hashlib.sha256(event).hexdigest()
    assert te.finish_stage(folder, RUN_ID, "after", {}) is None  # no such stage recorded
    assert te.finish_stage(folder, RUN_ID, "../before", {}) is None


def test_a_different_database_between_stages_is_flagged_in_the_manifest(rig, tmp_path):
    folder = tmp_path / "ev"
    te.record_stage(folder, take(rig, "before"), {})
    other = take(rig, "after")
    other["system_identifier"] = "7399999999999999999"
    archive = te.record_stage(folder, other, {})
    with zipfile.ZipFile(archive) as z:
        assert json.loads(z.read("manifest.json"))["identity_consistent"] is False


def test_no_zip_for_an_unexpected_run_id_or_stage(tmp_path):
    assert te.refresh_zip(tmp_path, "../../x") is None
    assert te.record_stage(tmp_path, {"stage": "during", "run_id": RUN_ID}, {}) is None
    assert list(tmp_path.iterdir()) == []


def test_something_that_is_not_a_png_is_never_stored_as_a_picture(tmp_path):
    shot = {"stage": "before", "run_id": RUN_ID, "status": "CAPTURED", "mode": "terminal", "png": b"<html>"}
    archive = te.record_stage(tmp_path, shot, {})
    assert not (tmp_path / "before.png").exists()
    with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as z:
        assert "before.png" not in z.namelist()
