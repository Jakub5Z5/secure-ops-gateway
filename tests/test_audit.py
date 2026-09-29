import pytest

from secure_ops_gateway.audit import AuditError, JSONLAuditSink


def test_audit_file_rejects_symlink(tmp_path):
    victim = tmp_path / "victim.log"
    victim.write_text("do-not-touch")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(victim)
    with pytest.raises(AuditError, match="unsafe"):
        JSONLAuditSink(link)
    assert victim.read_text() == "do-not-touch"


def test_audit_parent_must_not_be_shared_writable(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    with pytest.raises(AuditError, match="unsafe"):
        JSONLAuditSink(unsafe / "audit.jsonl")



def test_audit_rejects_writable_nonsticky_ancestor(tmp_path):
    ancestor = tmp_path / "shared"
    ancestor.mkdir()
    ancestor.chmod(0o777)
    private = ancestor / "private"
    private.mkdir(mode=0o700)
    with pytest.raises(AuditError, match="unsafe"):
        JSONLAuditSink(private / "audit.jsonl")


def test_audit_rejects_parent_owned_by_unrelated_user(tmp_path, monkeypatch):
    # Simulate a privileged process evaluating a directory owned by another UID.
    actual_uid = __import__("os").geteuid()
    fake_uid = actual_uid + 10000 if actual_uid != 0 else 10000
    monkeypatch.setattr("secure_ops_gateway.paths.os.geteuid", lambda: fake_uid)
    with pytest.raises(AuditError, match="unsafe"):
        JSONLAuditSink(tmp_path / "audit.jsonl")


def test_audit_detects_parent_replacement_after_initialization(tmp_path):
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    sink = JSONLAuditSink(parent / "audit.jsonl")

    moved = tmp_path / "state-old"
    parent.rename(moved)
    parent.mkdir(mode=0o700)

    with pytest.raises(AuditError, match="safely"):
        sink({"event": "must-not-be-redirected"})
    assert not (parent / "audit.jsonl").exists()


def test_independent_audit_sinks_serialize_partial_writes(tmp_path, monkeypatch):
    import json
    import os
    import threading
    import time

    path = tmp_path / "audit.jsonl"
    sink_a = JSONLAuditSink(path)
    sink_b = JSONLAuditSink(path)
    real_write = os.write
    first_partial = threading.Event()
    release_first = threading.Event()
    seen_threads = set()
    guard = threading.Lock()

    def partial_write(fd, data):
        raw = bytes(data)
        tid = threading.get_ident()
        with guard:
            first_for_thread = tid not in seen_threads
            if first_for_thread:
                seen_threads.add(tid)
        if first_for_thread and len(raw) > 1:
            written = real_write(fd, raw[: max(1, len(raw) // 2)])
            if not first_partial.is_set():
                first_partial.set()
                assert release_first.wait(2)
            return written
        return real_write(fd, raw)

    monkeypatch.setattr("secure_ops_gateway.audit.os.write", partial_write)
    errors = []

    def run(sink, event):
        try:
            sink({"event": event, "payload": "x" * 200})
        except Exception as exc:  # pragma: no cover - assertion below exposes it.
            errors.append(exc)

    first = threading.Thread(target=run, args=(sink_a, "A"))
    second = threading.Thread(target=run, args=(sink_b, "B"))
    first.start()
    assert first_partial.wait(2)
    second.start()
    time.sleep(0.05)
    release_first.set()
    first.join(2)
    second.join(2)

    assert errors == []
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert {record["event"] for record in records} == {"A", "B"}


def test_audit_does_not_create_state_below_unrelated_owner(tmp_path, monkeypatch):
    import os

    attacker = tmp_path / "attacker-owned"
    attacker.mkdir(mode=0o700)
    actual_uid = os.geteuid()
    if actual_uid == 0:
        os.chown(attacker, 65534, -1)
    else:
        monkeypatch.setattr("secure_ops_gateway.paths.os.geteuid", lambda: actual_uid + 10000)

    state = attacker / "must-not-be-created"
    with pytest.raises(AuditError, match="unsafe"):
        JSONLAuditSink(state / "audit.jsonl")
    assert not state.exists()
