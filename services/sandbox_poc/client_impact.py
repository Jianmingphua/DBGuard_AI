"""Client-impact warnings for fixes that can break OTHER systems' connections (E2E Gate 1,
decision 3, ruled by Melvin 10 Nov 2026).

Hardening the server side does not update the clients. These fixes can lock out
applications that still use an old TLS version, a removed cipher, an address no longer
listened on, more connections than a new limit, or weak passwords in account scripts. Each
warning says, directly: what breaks, how many connections right now would be affected
(counted from the snapshot's own connection evidence; the collector is unchanged), what must
change on the client side, and how to confirm afterwards. All text is fixed here and
reviewed; nothing comes from model output. Counts are never guessed: hidden sessions are
reported as hidden, and a missing connections section says "could not be counted".
"""
from typing import Any

TLS_ORDER = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
TCP = ("loopback", "private", "public")
ADDRESS = {"loopback": "this server itself", "private": "a private network", "public": "a public network"}
# The four CIS 6.10 TLS 1.2 ciphers (backend catalog_checks.CIS_TLS12_CIPHERS).
CIS_TLS12_CIPHERS = ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
                     "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256")
HEADLINE = "CLIENT ACTION REQUIRED: this change will block clients that are not updated."
REMINDER = ("Your side being hardened does NOT mean these clients still work. Hardening the "
            "server does not update them.")

TEXT = {
    "tls_protocol": {
        "what_breaks": "After this fix the server refuses {old}. Clients that only speak those versions cannot connect.",
        "before_applying": "Upgrade every client (driver, library or application) that uses {old} to {new} or later.",
        "after_applying": "Confirm each affected application reconnects, and watch the server log for TLS handshake failures.",
    },
    "tls_cipher": {
        "what_breaks": ("After this fix only the four CIS TLS 1.2 ciphers remain (TLS 1.3 is unaffected). TLS 1.2 "
                        "clients without one of them fail to connect, and clients set to sslmode=prefer may "
                        "silently connect WITHOUT encryption."),
        "before_applying": ("Make sure every TLS 1.2 client supports one of the CIS ciphers (or uses TLS 1.3), and set "
                            "clients to sslmode=require or stricter so they never fall back to no encryption."),
        "after_applying": "Confirm each affected application reconnects with encryption (ssl = true in pg_stat_ssl).",
    },
    "listen_addresses": {
        "what_breaks": ("After this fix and the restart, the server only accepts network connections on the listed "
                        "addresses ({new}). Clients connecting through any other address cannot connect."),
        "before_applying": "Check that every application, tool and replica connects through an address that stays listed.",
        "after_applying": "Confirm each application reconnects after the restart, and keep console access in case it does not.",
    },
    "connection_limit": {
        "what_breaks": ("After this fix the account {role} may have at most {limit} connections at once. Further "
                        "connections from that account are refused."),
        "before_applying": ("Check the connection pool size of every application using {role} and lower it, or ask for "
                            "a higher limit in the company policy."),
        "after_applying": "Confirm the applications using {role} keep working at their busiest time.",
    },
    "password_check": {
        "what_breaks": ("After this fix and the restart, new or changed passwords that are too weak are refused. "
                        "Account-creation and password-change scripts that set weak passwords will fail."),
        "before_applying": "Check every script or tool that creates accounts or changes passwords, and update weak passwords they set.",
        "after_applying": "Run each account-creation and password-change script once and confirm it succeeds.",
    },
}


def _rows(snapshot: Any) -> tuple[list[dict] | None, int]:
    """(visible connection rows, hidden connection count); rows None when not collected."""
    baseline = snapshot.get("baseline") if isinstance(snapshot, dict) else None
    rows = baseline.get("connections") if isinstance(baseline, dict) else None
    if not isinstance(rows, list):
        return None, 0
    visible, hidden = [], 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        count = row.get("connection_count")
        count = count if isinstance(count, int) and not isinstance(count, bool) and count > 0 else 1
        if row.get("visible") is not True or row.get("client_addr_class") in (None, "not_visible") \
                or row.get("backend_type") is None:
            hidden += count
            continue
        # Review finding 2: replicas (walsender) are clients too; a TLS or address change
        # that breaks them breaks replication, so they are counted and labelled.
        if row.get("backend_type") not in ("client backend", "walsender"):
            continue
        visible.append({**row, "connection_count": count})
    return visible, hidden


def _who(row: dict, *extra: str) -> dict:
    out = {"kind": "replication" if row.get("backend_type") == "walsender" else "client",
           "application": _s(row.get("application_name")), "user": _s(row.get("usename")),
           "database": _s(row.get("datname")),
           "network": ADDRESS.get(row.get("client_addr_class"), _s(row.get("client_addr_class"))),
           "connections": row["connection_count"]}
    for key in extra:
        out[key] = _s(row.get(key))
    return out


def _s(value: Any) -> str | None:
    return value[:120] if isinstance(value, str) and value else None


def _warning(kind: str, affected: list[dict] | None, hidden: int, **fmt: Any) -> dict:
    text = {k: v.format(**fmt) for k, v in TEXT[kind].items()}
    if affected is None:
        count_line = "Live connections could not be counted: the snapshot has no connection evidence."
        total = None
    else:
        total = sum(a["connections"] for a in affected)
        count_line = (f"{total} connection{'s' if total != 1 else ''} right now would be affected."
                      if total else "No live connection in the snapshot would be affected right now.")
        if hidden:
            count_line += (f" {hidden} more connection{'s' if hidden != 1 else ''} could not be seen by the "
                           "collector and may also be affected.")
    return {"kind": kind, "required": True, "headline": HEADLINE, **text, "count_line": count_line,
            "affected_connections": total, "hidden_connections": hidden if affected is not None else None,
            "affected": affected or [], "reminder": REMINDER,
            "basis": "Counted from the snapshot's connection evidence (pg_stat_activity and pg_stat_ssl) at collection time."}


def tls_protocol(snapshot: Any, proposed: Any) -> dict | None:
    if proposed not in TLS_ORDER:
        return None
    old = TLS_ORDER[:TLS_ORDER.index(proposed)]
    if not old:
        return None
    rows, hidden = _rows(snapshot)
    affected = None if rows is None else [
        _who(r, "tls_version") for r in rows
        if r.get("client_addr_class") in TCP and r.get("ssl") is True and r.get("tls_version") in old]
    return _warning("tls_protocol", affected, hidden, old=" and ".join(old), new=proposed)


def tls_cipher(snapshot: Any) -> dict:
    rows, hidden = _rows(snapshot)
    affected = None if rows is None else [
        _who(r, "tls_cipher") for r in rows
        if r.get("client_addr_class") in TCP and r.get("ssl") is True and r.get("tls_version") == "TLSv1.2"
        and r.get("tls_cipher") not in CIS_TLS12_CIPHERS]
    return _warning("tls_cipher", affected, hidden)


def listen_addresses(snapshot: Any, proposed: Any) -> dict:
    rows, hidden = _rows(snapshot)
    # Which address each client used is not collected, so every network connection is listed.
    affected = None if rows is None else [
        _who(r) for r in rows if r.get("client_addr_class") in ("private", "public")]
    warning = _warning("listen_addresses", affected, hidden, new=_s(str(proposed)) or "the listed addresses")
    if affected:
        warning["count_line"] = warning["count_line"].replace(
            "would be affected", "come over the network: check each one uses an address that stays listed")
    return warning


def connection_limit(snapshot: Any, role: str, limit: int) -> dict:
    rows, hidden = _rows(snapshot)
    affected = None if rows is None else [_who(r) for r in rows if r.get("usename") == role]
    warning = _warning("connection_limit", affected, hidden, role=role, limit=limit)
    if affected is not None:
        now = sum(a["connections"] for a in affected)
        warning["affected_connections"] = max(0, now - limit) if now > limit else 0
        warning["count_line"] = (
            f"{role} has {now} connection{'s' if now != 1 else ''} right now; the new limit is {limit}. "
            + ("Connections above the limit would be refused." if now > limit
               else "Busier times may still go over it: check the pool sizes.")
            + (f" {hidden} more connection{'s' if hidden != 1 else ''} could not be seen by the collector."
               if hidden else ""))
    return warning


def password_check(snapshot: Any) -> dict:
    warning = _warning("password_check", [], 0)
    warning["count_line"] = "This cannot be counted from live connections: it affects scripts that set passwords."
    warning["affected_connections"] = None
    return warning


SETTINGS = {"ssl_min_protocol_version": lambda snap, value: tls_protocol(snap, value),
            "listen_addresses": lambda snap, value: listen_addresses(snap, value)}
CATALOG = {"tls_cipher_suites": lambda snap: tls_cipher(snap),
           "password_complexity_module": lambda snap: password_check(snap)}


def for_setting(snapshot: Any, setting: str, proposed: Any) -> dict | None:
    build = SETTINGS.get(setting)
    return build(snapshot, proposed) if build else None


def for_catalog(snapshot: Any, evaluator: str) -> dict | None:
    build = CATALOG.get(evaluator)
    return build(snapshot) if build else None


def of_result(result: Any) -> dict | None:
    """The warning recorded with a sandbox run (setting, catalog or object fix)."""
    if not isinstance(result, dict):
        return None
    for source in (result.get("risk_review"), result.get("proposal")):
        if isinstance(source, dict) and isinstance(source.get("client_impact"), dict):
            return source["client_impact"]
    return None


def text_block(fix_id: str, title: str | None, warning: dict) -> str:
    """Plain text for CLIENT-ACTIONS.txt and README files."""
    lines = [f"[{fix_id}] {title or ''}".rstrip(), "  " + warning["headline"],
             "  What breaks: " + warning["what_breaks"], "  Right now: " + warning["count_line"]]
    for a in warning.get("affected", [])[:50]:
        parts = [f"{k}={v}" for k, v in a.items() if v not in (None, "")]
        lines.append("    - " + ", ".join(parts))
    lines += ["  BEFORE applying: " + warning["before_applying"],
              "  AFTER applying: " + warning["after_applying"], "  " + warning["reminder"], ""]
    return "\n".join(lines)
