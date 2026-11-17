"""The DBA runner sorts configuration-file rows byte by byte, like the recorded states.

Found by the live package test (16 Nov): a target whose collation ignores "_" (en_US)
returned pg_file_settings ordered "logging_collector" before "log_truncate_on_rotation",
while the recorded states (provenance.signature) sort them the other way, so a correctly
applied fix failed verification.
"""
from services.sandbox_poc.bundle_assets import runner


class Cursor:
    def __init__(self):
        self.results = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        if "pg_settings" in sql:
            self.results = [("logging_collector", "on", "configuration file", "/d/postgresql.auto.conf",
                             "postmaster", False)]
        else:  # the order an en_US collation returns
            self.results = [("logging_collector", "on", "/d/postgresql.auto.conf", True, None),
                            ("log_truncate_on_rotation", "on", "/d/postgresql.auto.conf", True, None)]

    def fetchall(self):
        return self.results


class Conn:
    def cursor(self):
        return Cursor()


def test_file_rows_are_sorted_byte_by_byte_like_the_recorded_states():
    fp = runner.fingerprint(Conn(), ["logging_collector", "log_truncate_on_rotation"])
    assert [r["name"] for r in fp["file_settings"]] == ["log_truncate_on_rotation", "logging_collector"]
    assert [r["name"] for r in fp["file_settings"]] == sorted(r["name"] for r in fp["file_settings"])


def test_differing_names_lists_only_setting_names():
    a = {"settings": {"x_y": {"setting": "on"}, "z": {"setting": "1"}}, "file_settings": []}
    b = {"settings": {"x_y": {"setting": "off"}, "z": {"setting": "1"}}, "file_settings": []}
    assert runner.differing_names(a, b) == " (differs: x_y)"
    assert runner.differing_names(a, a) == ""
    assert runner.differing_names({"role": 1}, {"role": 2}) == ""
