"""Client-impact warnings (E2E Gate 1, decision 3, ruled by Melvin 10 Nov 2026).

Fixes that harden the server can lock out clients that are not updated. The warning must be
direct, count the live connections that would be affected from the snapshot's own evidence,
never guess (hidden or missing evidence is said plainly), and travel into the package.
"""
import copy

import pytest

from services.sandbox_poc import client_impact as ci
from test_sandbox_poc import engine, snapshot  # noqa: F401  shared fixtures

SNAP = {"baseline": {"connections": [
    {"backend_type": "client backend", "visible": True, "client_addr_class": "private", "connection_count": 3,
     "usename": "billing_svc", "datname": "appdb", "application_name": "billing", "ssl": True,
     "tls_version": "TLSv1.1", "tls_cipher": "ECDHE-RSA-AES256-SHA"},
    {"backend_type": "client backend", "visible": True, "client_addr_class": "private", "connection_count": 2,
     "usename": "web", "datname": "appdb", "application_name": "web", "ssl": True,
     "tls_version": "TLSv1.2", "tls_cipher": "AES128-SHA"},
    {"backend_type": "client backend", "visible": True, "client_addr_class": "public", "connection_count": 4,
     "usename": "web", "datname": "appdb", "application_name": "web", "ssl": True,
     "tls_version": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384"},
    {"backend_type": "client backend", "visible": True, "client_addr_class": "unix_socket", "connection_count": 1,
     "usename": "postgres", "datname": "postgres", "application_name": "psql"},
    {"backend_type": "autovacuum launcher", "visible": True, "client_addr_class": "unix_socket", "connection_count": 1},
    {"backend_type": None, "visible": False, "client_addr_class": "not_visible", "connection_count": 2},
]}}


def test_tls_minimum_counts_only_clients_on_older_versions():
    w = ci.tls_protocol(SNAP, "TLSv1.2")
    assert w["headline"].startswith("CLIENT ACTION REQUIRED") and w["required"] is True
    assert "refuses TLSv1 and TLSv1.1" in w["what_breaks"]
    assert w["affected_connections"] == 3 and w["hidden_connections"] == 2
    assert w["affected"] == [{"kind": "client", "application": "billing", "user": "billing_svc",
                              "database": "appdb", "network": "a private network", "connections": 3,
                              "tls_version": "TLSv1.1"}]
    assert "3 connections right now would be affected" in w["count_line"]
    assert "2 more connections could not be seen" in w["count_line"]
    assert "does NOT mean these clients still work" in w["reminder"]
    assert "TLSv1.2 or later" in w["before_applying"]


def test_tls_13_only_would_list_the_tls_12_clients_too():
    w = ci.tls_protocol(SNAP, "TLSv1.3")
    assert w["affected_connections"] == 5


def test_ciphers_count_tls12_sessions_outside_the_cis_list_and_warn_of_silent_fallback():
    w = ci.tls_cipher(SNAP)
    assert w["affected_connections"] == 2 and w["affected"][0]["tls_cipher"] == "AES128-SHA"
    assert "WITHOUT encryption" in w["what_breaks"] and "sslmode=require" in w["before_applying"]


def test_listen_addresses_lists_every_network_client():
    w = ci.listen_addresses(SNAP, "10.0.0.5")
    assert w["affected_connections"] == 9 and "10.0.0.5" in w["what_breaks"]
    assert "come over the network" in w["count_line"]


def test_connection_limit_compares_current_connections_with_the_new_limit():
    over = ci.connection_limit(SNAP, "web", 4)
    assert over["affected_connections"] == 2
    assert "web has 6 connections right now; the new limit is 4" in over["count_line"]
    under = ci.connection_limit(SNAP, "web", 50)
    assert under["affected_connections"] == 0 and "pool sizes" in under["count_line"]


def test_password_check_is_never_given_a_made_up_count():
    w = ci.password_check(SNAP)
    assert w["affected_connections"] is None and "scripts" in w["count_line"]


def test_missing_connection_evidence_is_said_plainly_never_zero():
    w = ci.tls_protocol({"baseline": {}}, "TLSv1.2")
    assert w["affected_connections"] is None and "could not be counted" in w["count_line"]
    assert ci.tls_protocol(None, "TLSv1.2")["affected_connections"] is None


def test_unknown_values_and_settings_give_no_warning():
    assert ci.tls_protocol(SNAP, "TLSv1") is None
    assert ci.tls_protocol(SNAP, "bogus") is None
    assert ci.for_setting(SNAP, "log_connections", "on") is None
    assert ci.for_catalog(SNAP, "pgaudit_enabled") is None
    assert ci.for_setting(SNAP, "ssl_min_protocol_version", "TLSv1.2")["kind"] == "tls_protocol"
    assert ci.for_catalog(SNAP, "tls_cipher_suites")["kind"] == "tls_cipher"


def test_names_from_evidence_are_bounded_and_text_block_lists_them():
    snap = copy.deepcopy(SNAP)
    snap["baseline"]["connections"][0]["application_name"] = "x" * 500
    w = ci.tls_protocol(snap, "TLSv1.2")
    assert len(w["affected"][0]["application"]) == 120
    block = ci.text_block("fix-ssl_min_protocol_version", "Ensure TLS", ci.tls_protocol(SNAP, "TLSv1.2"))
    assert "BEFORE applying:" in block and "user=billing_svc" in block and "CLIENT ACTION REQUIRED" in block


def test_of_result_reads_setting_catalog_and_object_runs():
    w = ci.tls_cipher(SNAP)
    assert ci.of_result({"risk_review": {"client_impact": w}}) == w
    assert ci.of_result({"proposal": {"client_impact": w}}) == w
    assert ci.of_result({"risk_review": {}}) is None and ci.of_result(None) is None


def test_the_setting_review_carries_the_warning(engine, snapshot):
    from services.sandbox_poc.planning import risk_review
    from services.sandbox_poc.provenance import setting_rows
    snap = copy.deepcopy(snapshot)
    rows = setting_rows(snap)
    if "ssl_min_protocol_version" not in rows:
        pytest.skip("fixture has no ssl_min_protocol_version row")
    rows["ssl_min_protocol_version"].update(setting="TLSv1", context="sighup")
    snap.setdefault("baseline", {})["connections"] = SNAP["baseline"]["connections"]
    review = risk_review(engine, snap, "cis-pg17-v1.1.0:6.9")
    assert review["client_impact"]["kind"] == "tls_protocol"
    assert review["client_impact"]["affected_connections"] == 3
    log = risk_review(engine, snap, "cis-pg17-v1.1.0:3.1.20") if "log_connections" in rows else {}
    assert "client_impact" not in log


def test_replication_connections_are_counted_and_labelled():
    # Security review finding 2: a replica on TLS 1.1 must not be reported as "no one affected".
    snap = {"baseline": {"connections": [
        {"backend_type": "walsender", "visible": True, "client_addr_class": "private", "connection_count": 1,
         "usename": "replicator", "datname": None, "application_name": "standby1", "ssl": True,
         "tls_version": "TLSv1.1", "tls_cipher": "x"}]}}
    w = ci.tls_protocol(snap, "TLSv1.2")
    assert w["affected_connections"] == 1 and w["affected"][0]["kind"] == "replication"
    assert ci.listen_addresses(snap, "10.0.0.5")["affected_connections"] == 1
