"""The sandbox's standard log folder is writable in memory (fix of 12 Nov 2026).

Found in the demo: with log_directory=/var/log/postgresql (approved profile value, 3.1.4)
and logging_collector=on (3.1.3), PostgreSQL could not start after the combined restart,
because the sandbox's root file system is read-only. The folder is now an in-memory tmpfs
owned by the run, like the data and socket folders, and every other lock-down stays.
"""
from services.sandbox_poc import runtime as rt


def started_args(monkeypatch):
    calls = []

    def fake_docker(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return "sha256:abc linux/arm64"
        if args and args[0] == "run":
            raise RuntimeError("stop here")  # only the run arguments matter
        return ""

    monkeypatch.setattr(rt, "docker", fake_docker)
    monkeypatch.setattr(rt, "pinned_image_ids", lambda image: None)
    try:
        rt.DisposablePostgres().start()
    except RuntimeError:
        pass
    return next(c for c in calls if c and c[0] == "run")


def test_the_log_folder_is_an_in_memory_run_owned_folder(monkeypatch):
    args = list(started_args(monkeypatch))
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "--tmpfs"]
    assert "/var/log/postgresql:rw,uid=999,gid=999,mode=0770,size=64m" in mounts
    assert len(mounts) == 3  # data, socket and log folders only


def test_every_other_lock_down_stays(monkeypatch):
    args = list(started_args(monkeypatch))
    for flag in ("--read-only", "--cap-drop", "--security-opt"):
        assert flag in args
    assert args[args.index("--network") + 1] == "none"
    assert "-v" not in args and "--volume" not in args and "--mount" not in args
