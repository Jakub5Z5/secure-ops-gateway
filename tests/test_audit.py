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
