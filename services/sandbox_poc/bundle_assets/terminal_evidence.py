"""Before / after / after-undo pictures of fixed read-only queries on the DBA's own database.

E2E Gate 1, decision 2 (Melvin, 10 Nov 2026; replaces Task 2 Gate 1 ruling #6). This file
ships inside the combined package and runs only when the DBA runs ``harden.sh``. It needs
Python 3 and psycopg2; VHS, ttyd, ffmpeg and psql for a terminal picture; Playwright for the
rendered fallback (visual_evidence.py). Adapted from services/sandbox_poc/terminal_capture.py.

- Connection details never reach the tape, the typed line, the SQL file or the picture.
  DBGUARD_DSN is parsed with psycopg2.extensions.parse_dsn. A private folder is made with
  tempfile.mkdtemp (0700) in the system temp folder (refused if its path shows the home
  folder or a user name). It holds ``pg_service.conf`` (0600, section ``[dbguard]``, no
  password) and ``.pgpass`` (0600). PGSERVICEFILE and PGPASSFILE are set only in the VHS
  child's minimal environment (VHS passes it to the recorded shell). Everything is deleted
  in a ``finally``, after success, failure and timeout.
- VHS types exactly one fixed command: ``<psql> service=dbguard -X -e -v ON_ERROR_STOP=1 -f
  <private folder>/dbguard-<stage>.sql``. ``<psql>`` must be one of PSQL_PATHS. The line must
  pass the strict character filter and the tape must equal the fixed template line by line.
- The SQL file starts read-only and pins search_path, then holds only fixed templates:
  identity (database, version, the package run ID), the changed settings (SHOW plus one
  pg_settings query) and the one role, table or function of each object fix. Never
  inet_server_addr/port, pg_authid, passwords, keys or DSN values. check_sql() looks again.
- The same queries are first run through psycopg2 in a read-only session. Their output is
  masked with the collector's redaction rules and with every connection value (host, port,
  user, password). If masking changed anything, the terminal picture (which cannot be
  masked) is refused and the rendered picture shows the masked output.
- A capture problem never raises: it becomes a reason, the rendered picture is the fallback,
  and the apply/verify/rollback result is never changed by it.

The raw (masked) output and its sha256 are the authority; each picture shows run ID, stage,
target ID, UTC time and that sha256.
"""
from __future__ import annotations

import base64
import functools
import getpass
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unicodedata
import zipfile
from datetime import datetime, timezone
from pathlib import Path

STAGES = {"before": "BEFORE", "after": "AFTER FIX", "rollback": "AFTER ROLLBACK"}
SCREENSHOT_MODES = ("terminal", "rendered", "off")

READ_ONLY_LINE = "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;"
FIXED_SETS = ("SET search_path = pg_catalog, pg_temp", "SET standard_conforming_strings = on")
SENTINEL_TEXT = "end of dbguard evidence"
SENTINEL_SHOWN = SENTINEL_TEXT.upper()  # only psql's output row is upper case, never the echo
SERVICE_NAME = "dbguard"
MASK = "***MASKED***"

# Standard system locations only: a per-user install would show the user name when typed.
PSQL_PATHS = (
    "/usr/bin/psql", "/usr/local/bin/psql", "/opt/homebrew/bin/psql",
    "/usr/pgsql-17/bin/psql", "/usr/lib/postgresql/17/bin/psql",
    "/opt/homebrew/opt/libpq/bin/psql", "/usr/local/opt/libpq/bin/psql",
)  # every entry must pass TYPED_ALLOWED (so no postgresql@17 keg paths: '@' is never typed)
TOOL_DIR = re.compile(r"/[A-Za-z0-9/._-]+")
PRIVATE_DIR = re.compile(r"/[A-Za-z0-9/._-]+")
SETTING_NAME = re.compile(r"[a-z_][a-z0-9_.]*")
RUN_ID = re.compile(r"[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
TYPED_ALLOWED = re.compile(r"[A-Za-z0-9 /._=-]+")
FORBIDDEN_TYPED = frozenset("'\"`\\$;|&<>\n\r")
VHS_TIMEOUT_SECONDS = 60
MAX_SQL_BYTES = 64 * 1024
PG_IDENTIFIER_MAX_BYTES = 63
LINE_PIXELS, PADDING_PIXELS, COLUMNS = 18, 48, 150

# Fixed geometries; the smallest that fits the expected output is used.
GEOMETRY = ((1400, 1100), (1400, 2000), (1400, 3200), (1400, 4800))

TAPE_TEMPLATE = """Set Shell "bash"
Set FontSize 14
Set Width {width}
Set Height {height}
Set Padding 24
Set TypingSpeed 5ms
Hide
Type "exec env PS1='evidence$ ' HISTFILE=/dev/null TERM=xterm-256color bash --norc --noprofile"
Enter
Type "clear"
Enter
Sleep 300ms
Show
Type "{typed}"
Enter
Wait+Screen@45s /{sentinel}/
Wait+Line@10s /evidence/
Sleep 500ms
Screenshot shot.png
Sleep 500ms
"""

TYPED_TEMPLATE = "{psql} service=" + SERVICE_NAME + " -X -e -v ON_ERROR_STOP=1 -f {path}"


class CaptureRefused(Exception):
    """A safety check refused this terminal picture; the message is a fixed reason."""


# ---------------------------------------------------------------------------
# Tools and the browser VHS uses (never downloaded during a capture)
# ---------------------------------------------------------------------------

_VERSION_TEXT = re.compile(r"[ -~]{1,120}")


def _version(path, flag):
    if not path:
        return None
    try:
        out = subprocess.run([path, flag], capture_output=True, text=True, timeout=10,
                             env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.SubprocessError):
        return None
    line = ((out.stdout or out.stderr or "").strip().splitlines() or [""])[0].strip()
    return line if out.returncode == 0 and _VERSION_TEXT.fullmatch(line) else None


def psql_path():
    """The first executable psql among the standard system paths, else None."""
    for path in PSQL_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def tools():
    return {"vhs": _version(shutil.which("vhs"), "--version"),
            "ttyd": _version(shutil.which("ttyd"), "--version"),
            "ffmpeg": _version(shutil.which("ffmpeg"), "-version"),
            "psql": _version(psql_path(), "--version"),
            "browser": browser_info()}


SYSTEM_BROWSERS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge", "/snap/bin/chromium",
)
ROD_EXECUTABLES = ("Chromium.app/Contents/MacOS/Chromium", "chrome-linux/chrome", "chrome")
ROD_REVISION = re.compile(r"chromium-[0-9]{1,12}")
BROWSER_SETUP = ("The terminal browser is not set up: VHS needs its Chromium in ~/.cache/rod/browser (or a "
                 "system Chrome/Chromium) and this package never lets it download one. Set it up once while "
                 "online by running VHS on any small tape (for example one that only types `echo ok`)")


def _rod_root():
    return Path.home() / ".cache" / "rod" / "browser"


def _rod_executable(folder):
    for rel in ROD_EXECUTABLES:
        candidate = folder / rel
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def terminal_browser():
    for path in SYSTEM_BROWSERS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return {"source": "system", "executable": path, "revisions": []}
    root = _rod_root()
    try:
        folders = sorted((d for d in root.iterdir()
                          if ROD_REVISION.fullmatch(d.name) and d.is_dir() and not d.is_symlink()
                          and _rod_executable(d)), key=lambda d: int(d.name.split("-")[1]))
    except OSError:
        return None
    if not folders:
        return None
    return {"source": "rod-cache", "executable": str(_rod_executable(folders[-1])),
            "revisions": [d.name for d in folders], "root": str(root)}


def _display_path(path):
    home = str(Path.home())
    return "~" + path[len(home):] if path.startswith(home + "/") else path


@functools.lru_cache(maxsize=8)
def _browser_version(executable):
    return _version(executable, "--version")


def browser_info():
    browser = terminal_browser()
    if browser is None:
        return None
    return {"source": browser["source"], "path": _display_path(browser["executable"]),
            "version": _browser_version(browser["executable"])}


# ---------------------------------------------------------------------------
# Connection values: parsed, masked, written only to private 0600 files
# ---------------------------------------------------------------------------

# Keys copied into pg_service.conf. password/passfile never are; anything else refuses.
SERVICE_KEYS = ("host", "hostaddr", "port", "dbname", "user", "sslmode", "sslrootcert", "sslcert",
                "sslkey", "sslcrl", "sslcrldir", "sslsni", "sslcompression", "ssl_min_protocol_version",
                "ssl_max_protocol_version", "requirepeer", "gssencmode", "krbsrvname", "gsslib",
                "channel_binding", "require_auth", "target_session_attrs", "connect_timeout",
                "keepalives", "keepalives_idle", "keepalives_interval", "keepalives_count")
IGNORED_KEYS = ("password", "passfile", "application_name", "fallback_application_name")
# Effective values (after libpq read its environment and defaults) that override the DSN's.
EFFECTIVE_KEYS = ("host", "hostaddr", "port", "dbname", "user", "sslmode", "sslrootcert", "sslcert",
                  "sslkey", "sslcrl", "target_session_attrs", "channel_binding")
SECRET_KEYS = ("host", "hostaddr", "port", "user", "password")
CASE_FREE_KEYS = ("host", "hostaddr")


def parse_dsn(dsn):
    from psycopg2.extensions import parse_dsn as _parse
    return dict(_parse(dsn))


def secret_values(params):
    """{value: case_insensitive} for every connection value that must never be shown."""
    out = {}
    for key in SECRET_KEYS:
        value = params.get(key)
        if not isinstance(value, str) or not value:
            continue
        parts = {value} | ({p.strip() for p in value.split(",")} if key != "password" else set())
        for part in parts:
            if len(part) >= 2:  # a single character identifies nothing and would mask everything
                out[part] = out.get(part, False) or key in CASE_FREE_KEYS
    return out


def mask(text, secrets):
    """(masked text, changed): the collector's redaction rules, then every connection value."""
    if not isinstance(text, str):
        return text, False
    masked = redact(text)
    for value in sorted(secrets, key=len, reverse=True):
        flags = re.I if secrets[value] else 0
        masked = re.sub(re.escape(value), MASK, masked, flags=flags)
    return masked, masked != text


def contains_secret(text, secrets):
    return mask(text, secrets)[1]


# Python port of collector/collect.sql pg_temp.mask_secrets (same patterns, same order).
_MASKS = (
    (re.compile(r"(password\s*=\s*)('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|(?:[^\s\\]|\\.)+)", re.I), r"\1***REDACTED***"),
    (re.compile(r"(passfile\s*=\s*)(\S+)", re.I), r"\1***REDACTED***"),
    (re.compile(r"(--password[= ])(\S+)", re.I), r"\1***REDACTED***"),
    (re.compile(r"://([^:/@\s]*):([^@\s]+)@"), r"://\1:***REDACTED***@"),
    (re.compile(r"([?&][^=&\s]*%[^=&\s]*=)[^&\s]*"), r"\1***REDACTED***"),
)


def redact(text):
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


def _service_value(value):
    if (not isinstance(value, str) or not value or len(value) > 1024 or value != value.strip()
            or any(ch in value for ch in "\n\r\0")):
        raise CaptureRefused("A connection value cannot be written to a private service file")
    return value


def service_params(dsn_params, effective):
    """The [dbguard] section: the DSN's own keys, then libpq's effective values. No password."""
    unknown = sorted(k for k in dsn_params if k not in SERVICE_KEYS and k not in IGNORED_KEYS)
    if unknown:
        raise CaptureRefused("DBGUARD_DSN uses a connection option the terminal picture does not copy "
                             "(for example service or options)")
    params = {k: v for k, v in dsn_params.items() if k in SERVICE_KEYS}
    for key in EFFECTIVE_KEYS:
        value = (effective or {}).get(key)
        if isinstance(value, str) and value:
            params[key] = value
    return {k: _service_value(str(v)) for k, v in params.items()}


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def write_connection_files(folder, params, password):
    """pg_service.conf and .pgpass (both 0600) in the private folder; the env that points at them."""
    service = os.path.join(folder, "pg_service.conf")
    passfile = os.path.join(folder, ".pgpass")
    _write_private(service, "[" + SERVICE_NAME + "]\n" + "".join(f"{k}={v}\n" for k, v in params.items()))
    if password:
        if any(ch in password for ch in "\n\r\0"):
            raise CaptureRefused("The password cannot be written to a private password file")
        escaped = password.replace("\\", "\\\\").replace(":", "\\:")
        _write_private(passfile, "*:*:*:*:" + escaped + "\n")
    return {"PGSERVICEFILE": service, "PGPASSFILE": passfile}


def _temp_root():
    return tempfile.gettempdir()


def _user_names():
    names = set()
    for getter in (getpass.getuser, lambda: os.environ.get("USER"), lambda: os.environ.get("LOGNAME")):
        try:
            name = getter()
        except Exception:
            name = None
        if name:
            names.add(name)
    try:
        import pwd
        names.add(pwd.getpwuid(os.getuid()).pw_name)
    except Exception:
        pass
    return names


def _anonymous(path):
    """True when the path shows neither the home folder nor a user name."""
    if not PRIVATE_DIR.fullmatch(path):
        return False
    home = os.path.expanduser("~")
    for candidate in {path, os.path.realpath(path)}:
        for root in {home, os.path.realpath(home)}:
            if root not in ("", "/") and (candidate == root or candidate.startswith(root.rstrip("/") + "/")):
                return False
        parts = [p.lower() for p in candidate.split("/") if p]
        for name in _user_names():
            if name.lower() in parts or (len(name) >= 3 and name.lower() in candidate.lower()):
                return False
    return True


def private_dir():
    """A fresh 0700 folder in the system temp folder whose path names no user."""
    path = tempfile.mkdtemp(prefix="dbguard-pkg-", dir=_temp_root())
    os.chmod(path, 0o700)
    if not _anonymous(path):
        _remove(path)
        raise CaptureRefused("The system temp folder path shows the home folder or a user name; it would "
                             "be typed and pictured")
    return path


def _home_folders(workdir):
    home = Path(workdir) / "home"
    rod = home / ".cache" / "rod" / "browser"
    return [str(rod), str(rod.parent), str(rod.parent.parent), str(home)]


def _remove(path):
    for folder in _home_folders(path):
        try:
            if os.path.isdir(folder) and not os.path.islink(folder):
                os.chmod(folder, 0o700)
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Fixed SQL templates
# ---------------------------------------------------------------------------

def _checked_text(value, limit):
    if (not isinstance(value, str) or not value or "\\" in value or len(value.encode("utf-8")) > limit
            or any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp") for c in value)):
        raise CaptureRefused("An object name cannot be shown safely in a terminal picture")
    return value


def _lit(value, limit=PG_IDENTIFIER_MAX_BYTES):
    """A SQL string literal for an evidence name (identifier check, quotes doubled, no backslash)."""
    return "'" + _checked_text(value, limit).replace("'", "''") + "'"


COLLECTOR_SECRET_SETTINGS = frozenset({
    "archive_command", "restore_command", "archive_cleanup_command",
    "recovery_end_command", "primary_conninfo", "ssl_passphrase_command",
    "krb_server_keyfile",
})
COLLECTOR_REVIEWED_CUSTOM_SETTINGS = frozenset({
    "pgaudit.log", "pgaudit.log_catalog", "pgaudit.log_client",
    "pgaudit.log_level", "pgaudit.log_parameter",
    "pgaudit.log_parameter_max_size", "pgaudit.log_relation",
    "pgaudit.log_rows", "pgaudit.log_statement",
    "pgaudit.log_statement_once", "pgaudit.role",
    "set_user.block_alter_system", "set_user.block_copy_program",
    "set_user.block_log_statement", "set_user.exit_on_error",
    "set_user.nosuperuser_target_allowlist",
    "set_user.superuser_allowlist", "set_user.superuser_audit_tag",
    "pg_stat_statements.max", "pg_stat_statements.track",
    "pg_stat_statements.track_utility", "pg_stat_statements.track_planning",
    "pg_stat_statements.save",
    "plpgsql.variable_conflict", "plpgsql.print_strict_params",
    "plpgsql.check_asserts", "plpgsql.extra_warnings", "plpgsql.extra_errors",
})


def collector_redacts(name):
    """Mirror of app.services.spec_engine.redaction.collector_redacts (a test compares them)."""
    lowered = name.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
    if lowered in COLLECTOR_SECRET_SETTINGS:
        return True
    return "." in lowered and lowered not in COLLECTOR_REVIEWED_CUSTOM_SETTINGS


def _setting_name(name):
    if not isinstance(name, str) or not SETTING_NAME.fullmatch(name):
        raise CaptureRefused("Unsupported setting name")
    if collector_redacts(name):
        raise CaptureRefused("The collector redacts this setting's value; it is never shown")
    return name


def targets_from_configs(configs):
    """{settings, objects} from the package's fix.json files (checked against their manifests)."""
    settings, objects = [], []
    for config in configs:
        if config.get("kind") == "object":
            kind = (config.get("prior") or {}).get("kind")
            objects.append({"kind": kind, "target": config.get("target")})
        elif config.get("kind") == "catalog_setting":
            settings += list(config.get("settings") or [])
        else:
            settings.append(config.get("setting"))
    return {"settings": list(dict.fromkeys(settings)), "objects": objects}


ROLE_COLUMNS = ("rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, "
                "rolcanlogin, rolconnlimit")


def object_queries(item):
    if not isinstance(item, dict) or not isinstance(item.get("target"), dict):
        raise CaptureRefused("Object fix target is malformed")
    kind, target = item.get("kind"), item["target"]
    if kind == "role":
        return [("Role attributes", f"SELECT {ROLE_COLUMNS} FROM pg_catalog.pg_roles "
                                    f"WHERE rolname = {_lit(target.get('role'))};")]
    if kind == "function":
        args = target.get("identity_args")
        args_lit = "''" if args == "" else _lit(args, 1024)
        return [("Function security and EXECUTE privileges",
                 "SELECT n.nspname AS schema_name, p.proname AS function_name, "
                 "pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_args, p.prosecdef, p.proacl "
                 "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                 f"WHERE n.nspname = {_lit(target.get('schema'))} AND p.proname = {_lit(target.get('name'))} "
                 f"AND pg_catalog.pg_get_function_identity_arguments(p.oid) = {args_lit};")]
    if kind == "table":
        where = (f"WHERE n.nspname = {_lit(target.get('schema'))} AND c.relname = {_lit(target.get('table'))}")
        grantee = target.get("grantee")
        if grantee is None:
            return [("Table owner, privileges and row security",
                     "SELECT n.nspname AS schema_name, c.relname AS table_name, "
                     "pg_catalog.pg_get_userbyid(c.relowner) AS owner, c.relacl, c.relrowsecurity, "
                     "c.relforcerowsecurity FROM pg_catalog.pg_class c "
                     f"JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace {where};")]
        who = ("0" if grantee == "PUBLIC" else
               f"(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = {_lit(grantee)})")
        return [("Table privileges granted to this grantee",
                 "SELECT n.nspname AS schema_name, c.relname AS table_name, "
                 "CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee, "
                 "a.privilege_type, a.is_grantable "
                 "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                 "CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a "
                 f"{where} AND a.grantee = {who} ORDER BY a.privilege_type;")]
    raise CaptureRefused("Unsupported object fix kind")


def identity_query(run_id):
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise CaptureRefused("Unexpected package run ID")
    return ("Database identity",
            "SELECT pg_catalog.current_database() AS database, pg_catalog.version() AS server_version, "
            f"'{run_id}' AS run_id;")


def check_queries(cur, run_id, targets):
    """(title, sql): identity, each changed setting, all of them in pg_settings, then each object."""
    queries = [identity_query(run_id)]
    names = [_setting_name(n) for n in targets.get("settings", [])]
    for name in names:
        # SHOW errors on a custom setting that is not defined (pgaudit.log before its fix).
        cur.execute("SELECT pg_catalog.current_setting(%s, true) IS NOT NULL", (name,))
        defined = cur.fetchone()[0] is True
        shown = (f"SHOW {name};" if defined else
                 f"SELECT pg_catalog.current_setting({_lit(name)}, true) AS \"{name}\";")
        queries.append((f"Effective value of {name}", shown))
    if names:
        queries.append(("Value and source of the changed settings",
                        "SELECT name, setting, source FROM pg_catalog.pg_settings WHERE name IN ("
                        + ", ".join(_lit(n) for n in names) + ") ORDER BY name;"))
    for item in targets.get("objects", []):
        queries += object_queries(item)
    return queries


_SQL_FORBIDDEN = re.compile(r"[\\\x00-\x09\x0b-\x1f\x7f]")
_SQL_NEVER = re.compile(r"\b(?:pg_authid|rolpassword|pg_shadow|pg_user_mappings?|pg_read_(?:binary_)?file|"
                        r"pg_ls_\w+|pg_stat_file|lo_\w+|copy|ssl_key_file|pg_hba_file_rules|"
                        r"pg_reload_conf|set_config|pg_terminate_backend|pg_cancel_backend|"
                        r"default_transaction_read_only|inet_server_addr|inet_server_port|"
                        r"inet_client_addr|inet_client_port|pg_stat_activity|pg_stat_ssl|"
                        r"uescape|\w*to_xml\w*|xmlschema|regclass|regproc\w*)\b|\bread\s+write\b", re.I)


def _sql_statements(sql):
    """Statements with every '...' literal emptied; refuses comments, dollar signs, ampersands
    and text after the last semicolon (same rules as terminal_capture._sql_statements)."""
    statements, current, i, n = [], [], 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in "'\"":
            j = i + 1
            while True:
                k = sql.find(ch, j)
                if k < 0:
                    raise CaptureRefused("The evidence SQL has an unterminated quote")
                if sql[k + 1:k + 2] == ch:
                    j = k + 2
                    continue
                break
            current.append("''" if ch == "'" else sql[i:k + 1])
            i = k + 1
            continue
        if ch == "$":
            raise CaptureRefused("The evidence SQL has a dollar sign outside a string literal")
        if ch == "&":
            raise CaptureRefused("The evidence SQL has an ampersand outside a string literal")
        if sql.startswith("--", i) or sql.startswith("/*", i):
            raise CaptureRefused("The evidence SQL contains a comment")
        if ch == ";":
            statements.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    if "".join(current).strip():
        raise CaptureRefused("The evidence SQL has text after its last statement")
    return statements


def check_sql(sql):
    """Read-only first; then only the fixed SETs, SELECT or SHOW; no secrets catalog, address
    function, file function, configuration or session change; at most 64 KiB."""
    if (not isinstance(sql, str) or not sql.startswith(READ_ONLY_LINE + "\n")
            or len(sql.encode("utf-8")) > MAX_SQL_BYTES or _SQL_FORBIDDEN.search(sql)):
        raise CaptureRefused("The evidence SQL is outside the reviewed template")
    statements = _sql_statements(sql)
    if not statements or statements[0] + ";" != READ_ONLY_LINE:
        raise CaptureRefused("The evidence SQL does not start read-only")
    for statement in statements[1:]:
        if statement not in FIXED_SETS and not statement.startswith(("SELECT ", "SHOW ")):
            raise CaptureRefused("The evidence SQL has a statement outside the reviewed template")
    if _SQL_NEVER.search("\n".join(statements)):
        raise CaptureRefused("The evidence SQL names a secret-bearing catalog, an address or file function "
                             "or a configuration or session change")


def stamp_query(stage, run_id, target_id, captured_at, raw_sha):
    if (stage not in STAGES or not re.fullmatch(r"[0-9a-f]{64}", raw_sha or "")
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", captured_at or "")
            or not RUN_ID.fullmatch(run_id or "")):
        raise CaptureRefused("Evidence stamp values are malformed")
    rows = (("run_id", f"'{run_id}'"), ("stage", f"'{STAGES[stage]}'"), ("target_id", _lit(target_id, 128)),
            ("captured_utc", f"'{captured_at}'"), ("raw_output_sha256", f"'{raw_sha}'"))
    values = ", ".join(f"('{k}', {v})" for k, v in rows)
    return f"SELECT item, value FROM (VALUES {values}) AS dbguard_evidence(item, value);"


def evidence_sql(stamp, queries):
    body = [READ_ONLY_LINE, *[s + ";" for s in FIXED_SETS], stamp, *[q for _, q in queries],
            f"SELECT pg_catalog.upper('{SENTINEL_TEXT}') AS status;"]
    sql = "\n".join(body) + "\n"
    check_sql(sql)
    return sql


# ---------------------------------------------------------------------------
# Query output (psycopg2, read-only session)
# ---------------------------------------------------------------------------

def _cell(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "t" if value else "f"
    if isinstance(value, (list, tuple)):
        return "{" + ",".join("NULL" if v is None else str(v) for v in value) + "}"
    return str(value)


def _table_text(columns, rows):
    lines = [" | ".join(columns)]
    lines += [" | ".join("" if c is None else c for c in row) for row in rows]
    lines.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''})")
    return "\n".join(lines)


def run_queries(cur, queries, secrets):
    """Each check's output, masked; changed=True when masking altered anything."""
    out, changed = [], False
    for title, sql in queries:
        cur.execute(sql)
        columns = [d[0] for d in (cur.description or [])]
        rows = [[_cell(v) for v in row] for row in cur.fetchall()]
        masked_rows = []
        for row in rows:
            masked_row = []
            for cell in row:
                value, hit = mask(cell, secrets)
                changed = changed or hit
                masked_row.append(value)
            masked_rows.append(masked_row)
        query, hit = mask(sql, secrets)
        changed = changed or hit
        out.append({"title": title, "query": query, "columns": columns, "rows": masked_rows,
                    "output": _table_text(columns, masked_rows)})
    return out, changed


def digest(raw):
    return hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def geometry_for(sql, raw):
    """The smallest fixed geometry that fits the expected terminal output."""
    lines = 4 + 8  # prompt, stamp header and footer, sentinel
    lines += sum(-(-len(line) // COLUMNS) or 1 for line in sql.splitlines())
    for check in raw:
        lines += 3 + sum(-(-len(line) // COLUMNS) or 1 for line in check["output"].splitlines())
    needed = PADDING_PIXELS + lines * LINE_PIXELS
    for width, height in GEOMETRY:
        if needed <= height:
            return width, height
    raise CaptureRefused("Too much output for one terminal picture")


# ---------------------------------------------------------------------------
# Tape builder (the only place that produces text typed into a shell)
# ---------------------------------------------------------------------------

def check_typed(line):
    if (not isinstance(line, str) or not TYPED_ALLOWED.fullmatch(line)
            or any(ch in FORBIDDEN_TYPED or ord(ch) < 32 or ord(ch) == 127 for ch in line)):
        raise CaptureRefused("The typed command contains a character outside the fixed template")


def typed_command(psql, folder, stage, secrets):
    if psql not in PSQL_PATHS:
        raise CaptureRefused("psql is not at a standard path (" + ", ".join(PSQL_PATHS) + ")")
    if stage not in STAGES:
        raise CaptureRefused("Unknown evidence stage")
    if not _anonymous(folder) or contains_secret(folder, secrets):
        raise CaptureRefused("The private folder path cannot be typed safely")
    line = TYPED_TEMPLATE.format(psql=psql, path=f"{folder}/dbguard-{stage}.sql")
    check_typed(line)
    return line


def build_tape(typed, geometry):
    check_typed(typed)
    if geometry not in GEOMETRY:
        raise CaptureRefused("Unexpected terminal geometry")
    width, height = geometry
    tape = TAPE_TEMPLATE.format(width=width, height=height, typed=typed, sentinel=SENTINEL_SHOWN)
    check_tape(tape, typed)
    return tape


def check_tape(tape, typed):
    """The tape equals the fixed template line by line; only the one shown Type line varies."""
    if any((ord(ch) < 32 and ch != "\n") or ord(ch) == 127 or ord(ch) > 126 for ch in tape):
        raise CaptureRefused("The tape contains a control or non-ASCII character")
    lines = tape.splitlines()
    for width, height in GEOMETRY:
        template = TAPE_TEMPLATE.format(width=width, height=height, typed="\0", sentinel=SENTINEL_SHOWN).splitlines()
        if len(lines) == len(template) and all(
                line == want or (want == 'Type "\0"' and line == f'Type "{typed}"')
                for line, want in zip(lines, template)):
            if sum(line.startswith("Type ") for line in lines) == 3:
                return
    raise CaptureRefused("The tape differs from the fixed template")


# ---------------------------------------------------------------------------
# VHS runner (same safeguards as terminal_capture._run_vhs)
# ---------------------------------------------------------------------------

def _browser_home(workdir, browser):
    folders = _home_folders(workdir)
    rod = Path(folders[0])
    rod.mkdir(parents=True, mode=0o700)
    if browser.get("source") == "rod-cache":
        root = Path(browser["root"])
        for name in browser["revisions"]:
            if ROD_REVISION.fullmatch(name):
                (rod / name).symlink_to(root / name, target_is_directory=True)
    for folder in folders:
        os.chmod(folder, 0o500)
    return folders[-1]


def run_vhs(workdir, tape, connection_env):
    """Record the tape in the private folder; returns the PNG bytes. The caller deletes the folder."""
    vhs = shutil.which("vhs")
    if not vhs:
        raise CaptureRefused("VHS is not installed")
    dirs = []
    for tool in ("vhs", "ttyd", "ffmpeg"):
        path = shutil.which(tool)
        if not path:
            raise CaptureRefused(f"{tool} is not installed")
        folder = os.path.dirname(path)
        if not TOOL_DIR.fullmatch(folder):
            raise CaptureRefused("A capture tool path contains unexpected characters")
        dirs.append(folder)
    browser = terminal_browser()
    if browser is None:
        raise CaptureRefused(BROWSER_SETUP)
    (Path(workdir) / "stage.tape").write_text(tape)
    home = _browser_home(workdir, browser)
    # Minimal environment: tool folders, a private read-only HOME (no browser download), a
    # private TMPDIR, and the two connection files. VHS passes it on to the recorded shell.
    env = {"PATH": ":".join(dict.fromkeys(dirs + ["/usr/bin", "/bin"])), "HOME": home, "TMPDIR": workdir,
           "PGSERVICEFILE": connection_env["PGSERVICEFILE"], "PGPASSFILE": connection_env["PGPASSFILE"]}
    return _record(vhs, workdir, env)


def _record(vhs, workdir, env):
    process = subprocess.Popen([vhs, "stage.tape"], cwd=workdir, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    finished = False
    try:
        finished = _wait_unreaped(process, VHS_TIMEOUT_SECONDS)
    finally:
        # VHS is unreaped here (or, without os.waitid, possibly reaped: then its process-group
        # ID could have been reused, so only processes tied to the private folder are killed).
        _stop_recording(process, workdir, group=process.returncode is None)
        code = None
        try:
            code = process.wait(timeout=10)
        except subprocess.SubprocessError:
            pass
    if not finished:
        raise CaptureRefused(f"VHS did not finish within {VHS_TIMEOUT_SECONDS} seconds")
    if code != 0:
        raise CaptureRefused("VHS failed: the evidence query did not finish, or the terminal or its browser "
                             "did not start")
    shot = Path(workdir) / "shot.png"
    if not shot.is_file():
        raise CaptureRefused("VHS finished without writing the screenshot")
    png = shot.read_bytes()
    if not png.startswith(b"\x89PNG\r\n\x1a\n"):
        raise CaptureRefused("VHS wrote something that is not a PNG")
    return png


def _wait_unreaped(process, timeout):
    """Wait for VHS to exit without reaping it (WNOWAIT), so its PID stays reserved. Python
    builds without os.waitid (macOS before 3.13) poll instead, which reaps it."""
    deadline = time.monotonic() + timeout
    waitid = getattr(os, "waitid", None)
    while True:
        if waitid is not None:
            if waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
                return True
        elif process.poll() is not None:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def _stop_recording(process, workdir, group=True):
    """SIGKILL VHS's process group, its descendants and anything working in the private
    folder (ttyd, the recorded shell, psql, the browser). Never this process or its ancestors."""
    try:
        targets = _recording_processes(process.pid if group else None, workdir)
    except Exception:
        targets = set()
    if group:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    for pid in sorted(targets):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _recording_processes(leader, workdir):
    markers = {workdir, os.path.realpath(workdir)}
    uid = os.getuid()
    out = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,ppid=,pgid=,uid=,command="], capture_output=True,
                         text=True, timeout=10, env={"PATH": "/usr/bin:/bin"}).stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and all(x.lstrip("-").isdigit() for x in parts[:4]) and int(parts[3]) == uid:
            rows[int(parts[0])] = (int(parts[1]), int(parts[2]), parts[4] if len(parts) == 5 else "")
    children = {}
    for pid, (ppid, _, _) in rows.items():
        children.setdefault(ppid, []).append(pid)
    found, stack = set(), [leader] if leader is not None else []
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in found:
                found.add(child)
                stack.append(child)
    found |= {pid for pid, (_, pgid, command) in rows.items()
              if (leader is not None and pgid == leader) or any(m in command for m in markers)}
    try:
        found |= _processes_working_in(markers, uid)
    except Exception:
        pass
    keep, pid = {os.getpid()}, os.getpid()
    while pid in rows and pid > 1:
        pid = rows[pid][0]
        keep.add(pid)
    return {pid for pid in found if pid not in keep and pid != leader and pid > 1}


def _processes_working_in(markers, uid):
    lsof = next((p for p in ("/usr/sbin/lsof", "/usr/bin/lsof", "/sbin/lsof") if os.path.exists(p)), None)
    if lsof is None:
        return set()
    out = subprocess.run([lsof, "-a", "-d", "cwd", "-u", str(uid), "-Fpn"], capture_output=True, text=True,
                         timeout=10, env={"PATH": "/usr/bin:/bin"}).stdout
    found, pid = set(), None
    for line in out.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
        elif line.startswith("n") and pid is not None and any(
                line[1:] == m or line[1:].startswith(m + "/") for m in markers):
            found.add(pid)
    return found


# ---------------------------------------------------------------------------
# One stage
# ---------------------------------------------------------------------------

def _connect(dsn):
    import psycopg2
    return psycopg2.connect(dsn, connect_timeout=10)


def _effective(conn):
    try:
        return dict(conn.get_dsn_parameters())
    except Exception:
        return {}


def _password(conn, dsn_params):
    try:
        value = conn.info.password
    except Exception:
        value = None
    return value or dsn_params.get("password")


def _safe_target_id(target_id, secrets):
    try:
        _lit(target_id, 128)
    except CaptureRefused:
        return "not recorded"
    return target_id if not contains_secret(target_id, secrets) else MASK


def _rendered(stage, base, raw, reason):
    evidence = {"scope": "DBA TARGET · " + STAGES[stage], "run_id": base["run_id"], "stage": STAGES[stage],
                "target_id": base["target_id"], "captured_at": base["captured_at"],
                "raw_output_sha256": base["raw_output_sha256"], "note": reason,
                "queries": [{"title": q["title"], "query": q["query"], "output": q["output"]} for q in raw]}
    try:
        try:
            from . import visual_evidence  # imported as part of the services package (tests)
        except ImportError:
            import visual_evidence  # the package folder, next to this file
        shot = visual_evidence.capture(evidence)
        png = base64.b64decode(shot["png_base64"], validate=True)
    except Exception:
        return dict(base, status="UNAVAILABLE", mode="rendered",
                    reason=reason + " Rendered capture also failed (install playwright and its chromium).")
    return dict(base, status="CAPTURED", mode="rendered", png=png, sha256=hashlib.sha256(png).hexdigest(),
                reason=reason)


def capture(stage, *, dsn, run_id, target_id, targets, mode="terminal", connect=None):
    """One stage's evidence: query output always, then a terminal or rendered picture. Never raises.

    Returns {status: CAPTURED|UNAVAILABLE|OFF, mode, png (bytes, when captured), sha256, reason,
    typed_command, raw_output, raw_output_sha256, captured_at, database, system_identifier, tools}.
    """
    base = {"stage": stage if stage in STAGES else None, "stage_label": STAGES.get(stage),
            "run_id": run_id if isinstance(run_id, str) and RUN_ID.fullmatch(run_id) else None,
            "target_id": "not recorded", "captured_at": None, "raw_output": None, "raw_output_sha256": None,
            "database": None, "system_identifier": None, "typed_command": None,
            "tools": {"vhs": None, "ttyd": None, "ffmpeg": None, "psql": None, "browser": None}}
    try:
        return _capture(stage, base, dsn, run_id, target_id, targets, mode, connect or _connect)
    except Exception:
        return dict(base, status="UNAVAILABLE", mode=mode, reason="Screenshot capture failed; nothing was pictured.")


def _capture(stage, base, dsn, run_id, target_id, targets, mode, connect):
    if mode not in SCREENSHOT_MODES:
        mode = "terminal"
    try:
        if stage not in STAGES:
            raise CaptureRefused("Unknown evidence stage")
        dsn_params = parse_dsn(dsn)
        secrets = secret_values(dsn_params)
        conn = connect(dsn)
        try:
            conn.autocommit = True
            effective = _effective(conn)
            secrets.update(secret_values(effective))
            password = _password(conn, dsn_params)
            if password:
                secrets.update(secret_values({"password": password}))
            with conn.cursor() as cur:
                cur.execute(READ_ONLY_LINE)
                cur.execute("SET statement_timeout = '15s'")
                cur.execute("SET search_path = pg_catalog, pg_temp")
                cur.execute("SELECT pg_catalog.current_database()")
                base["database"] = cur.fetchone()[0]
                try:
                    cur.execute("SELECT system_identifier::text FROM pg_catalog.pg_control_system()")
                    base["system_identifier"] = cur.fetchone()[0]
                except Exception:
                    base["system_identifier"] = None
                queries = check_queries(cur, run_id, targets)
                raw, masked = run_queries(cur, queries, secrets)
        finally:
            try:
                conn.close()
            except Exception:
                pass
        base["target_id"] = _safe_target_id(target_id, secrets)
        captured_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        base.update(captured_at=captured_at, raw_output=raw, raw_output_sha256=digest(raw), redacted=masked)
        sql = evidence_sql(stamp_query(stage, run_id, base["target_id"], captured_at,
                                       base["raw_output_sha256"]), queries)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, CaptureRefused) else "The evidence queries could not be run"
        return dict(base, status="UNAVAILABLE", mode=mode, reason=reason + "; nothing was pictured.")
    if mode == "off":
        return dict(base, status="OFF", mode="off", reason="Screenshots turned off (--screenshots off).")
    if mode == "rendered":
        return _rendered(stage, base, raw, "Rendered capture chosen (--screenshots rendered).")
    try:
        base["tools"] = tools()
        if masked:
            raise CaptureRefused("The output showed a connection value or matched the collector's redaction "
                                 "rules; a terminal cannot be masked")
        if contains_secret(sql, secrets):
            raise CaptureRefused("The query text showed a connection value or matched the collector's redaction "
                                 "rules; psql would echo it")
        if not all(base["tools"][t] for t in ("vhs", "ttyd", "ffmpeg")):
            raise CaptureRefused("VHS, ttyd or ffmpeg is not installed")
        psql = psql_path()
        if psql is None:
            raise CaptureRefused("psql is not installed at a standard path (" + ", ".join(PSQL_PATHS) + ")")
        geometry = geometry_for(sql, raw)
        service = service_params(dsn_params, effective)
        png, typed = _terminal(stage, sql, service, password, psql, geometry, secrets)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, CaptureRefused) else "Terminal capture failed"
        return _rendered(stage, base, raw, f"Terminal capture UNAVAILABLE: {reason}. "
                                           "Rendered capture of the same queries used instead.")
    return dict(base, status="CAPTURED", mode="terminal", png=png, sha256=hashlib.sha256(png).hexdigest(),
                typed_command=typed, reason=None)


def _terminal(stage, sql, service, password, psql, geometry, secrets):
    """The private folder exists only inside this function; it is always deleted."""
    folder = private_dir()
    try:
        typed = typed_command(psql, folder, stage, secrets)
        tape = build_tape(typed, geometry)
        connection_env = write_connection_files(folder, service, password)
        sql_path = os.path.join(folder, f"dbguard-{stage}.sql")
        check_sql(sql)
        _write_private(sql_path, sql)
        png = run_vhs(folder, tape, connection_env)
        return png, typed
    finally:
        _remove(folder)


# ---------------------------------------------------------------------------
# Evidence files and target-evidence-<run_id>.zip (PNG + JSON only, fixed names)
# ---------------------------------------------------------------------------

def zip_members():
    return ([f"{s}.png" for s in STAGES] + [f"queries-{s}.json" for s in STAGES]
            + [f"event-{s}.json" for s in STAGES] + ["manifest.json"])


def _write_file(path, data):
    tmp = str(path) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def record_stage(evidence_dir, shot, step):
    """Write <stage>.png, queries-<stage>.json and event-<stage>.json, then refresh the zip."""
    stage = shot.get("stage")
    if stage not in STAGES:
        return None
    folder = Path(evidence_dir)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    png_path = folder / f"{stage}.png"
    if png_path.exists():
        png_path.unlink()  # never pair a stale picture with fresh query output
    png = shot.get("png")
    png_sha = None
    if shot.get("status") == "CAPTURED" and isinstance(png, bytes) and png.startswith(b"\x89PNG\r\n\x1a\n"):
        _write_file(png_path, png)
        png_sha = hashlib.sha256(png).hexdigest()
    queries = {"schema_version": "dbguard-target-queries-v1", "run_id": shot.get("run_id"), "stage": stage,
               "stage_label": STAGES[stage], "captured_at": shot.get("captured_at"),
               "raw_output_sha256": shot.get("raw_output_sha256"), "queries": shot.get("raw_output")}
    _write_file(folder / f"queries-{stage}.json", json.dumps(queries, indent=2).encode())
    event = {"schema_version": "dbguard-target-event-v1", "run_id": shot.get("run_id"), "stage": stage,
             "stage_label": STAGES[stage], "status": shot.get("status"), "mode": shot.get("mode"),
             "reason": shot.get("reason"), "tools": shot.get("tools"), "typed_command": shot.get("typed_command"),
             "png_member": f"{stage}.png" if png_sha else None, "png_sha256": png_sha,
             "raw_output_sha256": shot.get("raw_output_sha256"), "captured_at": shot.get("captured_at"),
             "database": shot.get("database"), "system_identifier": shot.get("system_identifier"),
             "target_id": shot.get("target_id"), "step": step}
    _write_file(folder / f"event-{stage}.json", json.dumps(event, indent=2).encode())
    return refresh_zip(evidence_dir, shot.get("run_id"))


def finish_stage(evidence_dir, run_id, stage, step):
    """Record the command's final result in event-<stage>.json and refresh the zip."""
    path = Path(evidence_dir) / f"event-{stage}.json"
    if stage not in STAGES or not path.is_file():
        return None
    event = json.loads(path.read_text())
    event["step"] = step
    _write_file(path, json.dumps(event, indent=2).encode())
    return refresh_zip(evidence_dir, run_id)


def refresh_zip(evidence_dir, run_id):
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        return None
    folder = Path(evidence_dir)
    files = {}
    for name in zip_members():
        if name != "manifest.json" and (folder / name).is_file():
            files[name] = (folder / name).read_bytes()
    events = [json.loads(files[f"event-{s}.json"]) for s in STAGES if f"event-{s}.json" in files]
    events.sort(key=lambda e: e.get("captured_at") or "")
    identities = {(e.get("database"), e.get("system_identifier")) for e in events if e.get("database")}
    latest = events[-1] if events else {}
    manifest = {"schema_version": "dbguard-target-evidence-v1", "run_id": run_id,
                "database": latest.get("database"), "system_identifier": latest.get("system_identifier"),
                "identity_consistent": len(identities) <= 1,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    files["manifest.json"] = json.dumps(manifest, indent=2).encode()
    target = folder / f"target-evidence-{run_id}.zip"
    tmp = str(target) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        with zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
    os.replace(tmp, target)
    return target
