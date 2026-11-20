import json
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from threading import Barrier

import pytest

from astranyx.engagement.ledger import REDACTED, AuditLedger, LedgerError, redact_url


def _assert_restricted_ledger_permissions(path):
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        return

    import win32security

    sd = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    control, _ = sd.GetSecurityDescriptorControl()
    assert control & 0x1000, "Windows ledger DACL must be protected"
    dacl = sd.GetSecurityDescriptorDacl()
    assert dacl is not None
    assert dacl.GetAceCount() == 3
    actual = set()
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        assert ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
        assert ace[1] == 0x1F01FF, "Unexpected Windows ledger ACE permissions"
        assert not (ace[0][1] & 0x10), "Inherited ACE is forbidden"
        actual.add(win32security.ConvertSidToStringSid(ace[2]))
    trusted = {
        "S-1-5-18",  # SYSTEM
        "S-1-5-32-544",  # Administrators
    }
    assert trusted.issubset(actual)
    assert len(actual) == 3  # SYSTEM, Administrators, current user


def append_many(path, start, count):
    ledger = AuditLedger(path, "eng-1")
    for index in range(start, start + count):
        ledger.append("event", {"index": index})
    return count


def test_ledger_chains_records_and_redacts_secrets(tmp_path):
    path = tmp_path / "actions.jsonl"
    ledger = AuditLedger(path, "eng-1")
    first = ledger.append(
        "request",
        {
            "url": "https://example.test/path?token=secret#fragment",
            "headers": {"Authorization": "Bearer secret", "Accept": "application/json"},
        },
    )
    second = ledger.append("response", {"status": 200})

    assert second["previous_hash"] == first["hash"]
    assert ledger.verify().valid
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[0]["data"]["url"] == f"https://example.test/path?{REDACTED}"
    assert records[0]["data"]["headers"]["Authorization"] == REDACTED
    _assert_restricted_ledger_permissions(path)


def test_ledger_detects_tampering_before_append(tmp_path):
    path = tmp_path / "actions.jsonl"
    ledger = AuditLedger(path, "eng-1")
    ledger.append("request", {"status": "allowed"})
    path.write_text(path.read_text().replace("allowed", "denied"), encoding="utf-8")

    result = ledger.verify()
    assert not result.valid
    assert "hash" in result.error
    with pytest.raises(LedgerError):
        ledger.append("response", {"status": 200})


def test_redacts_api_keys_and_malformed_url_ports_fail_safely(tmp_path):
    ledger = AuditLedger(tmp_path / "actions.jsonl", "eng-1")
    record = ledger.append(
        "request",
        {
            "headers": {"X-Api-Key": "sensitive", "Client-Secret": "sensitive"},
            "url": "https://example.test:invalid/path?secret=value",
        },
    )
    assert record["data"]["headers"]["X-Api-Key"] == REDACTED
    assert record["data"]["headers"]["Client-Secret"] == REDACTED
    assert REDACTED in record["data"]["url"]
    assert redact_url("not a URL") == "not a URL"


def test_partial_os_write_is_completed(tmp_path, monkeypatch):
    path = tmp_path / "actions.jsonl"
    ledger = AuditLedger(path, "eng-1")
    real_write = os.write
    calls = 0

    def partial_write(descriptor, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            midpoint = max(1, len(data) // 2)
            return real_write(descriptor, data[:midpoint])
        return real_write(descriptor, data)

    monkeypatch.setattr(os, "write", partial_write)
    ledger.append("request", {"status": "allowed"})
    assert calls >= 2
    assert ledger.verify().valid


def test_concurrent_appends_preserve_one_valid_chain(tmp_path, monkeypatch):
    path = tmp_path / "actions.jsonl"
    ledger = AuditLedger(path, "eng-1")
    workers = 8
    barrier = Barrier(workers)
    original_verify = ledger.verify
    initial = original_verify()
    calls = 0

    def synchronized_initial_verify():
        nonlocal calls
        calls += 1
        if calls <= workers:
            barrier.wait(timeout=2)
            return initial
        return original_verify()

    monkeypatch.setattr(ledger, "verify", synchronized_initial_verify)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(
            pool.map(
                lambda index: ledger.append("event", {"index": index}), range(workers)
            )
        )

    result = original_verify()
    assert result.valid
    assert result.records == workers


def test_cross_process_appends_preserve_chain(tmp_path):
    path = tmp_path / "actions.jsonl"
    workers = 4
    records_per_worker = 20
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                append_many, path, worker * records_per_worker, records_per_worker
            )
            for worker in range(workers)
        ]
        assert [future.result(timeout=10) for future in futures] == [20] * workers
    result = AuditLedger(path, "eng-1").verify()
    assert result.valid
    assert result.records == workers * records_per_worker


def test_tail_truncation_is_detected_by_head_checkpoint(tmp_path):
    path = tmp_path / "actions.jsonl"
    ledger = AuditLedger(path, "eng-1")
    ledger.append("first", {})
    ledger.append("second", {})
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:-1]), encoding="utf-8")
    result = ledger.verify()
    assert not result.valid
    assert "checkpoint" in result.error


def test_precreated_ledger_permissions_are_tightened(tmp_path):
    path = tmp_path / "actions.jsonl"
    path.touch(mode=0o644)
    ledger = AuditLedger(path, "eng-1")
    ledger.append("event", {})
    _assert_restricted_ledger_permissions(path)


def test_rejects_oversized_records_and_unsafe_event_names(tmp_path):
    ledger = AuditLedger(
        tmp_path / "actions.jsonl",
        "eng-1",
        max_bytes=1024,
        max_record_bytes=512,
    )
    with pytest.raises(LedgerError, match="record"):
        ledger.append("event", {"value": "A" * 1024})
    with pytest.raises(LedgerError, match="identifier"):
        ledger.append("event\nsecret", {})


def test_lock_descriptor_closed_when_permission_enforcement_fails(
    tmp_path, monkeypatch
):
    import errno
    import importlib
    import os

    module = importlib.import_module("astranyx.engagement.ledger")
    ledger = module.AuditLedger(tmp_path / "audit.jsonl", "eng-1")
    captured = {}

    def fail_permissions(descriptor, path):
        captured["descriptor"] = descriptor
        raise RuntimeError("simulated ACL failure")

    monkeypatch.setattr(module, "_secure_file_mode", fail_permissions)
    with (
        pytest.raises(RuntimeError, match="simulated ACL failure"),
        ledger._exclusive_lock(),
    ):
        pytest.fail("Lock unexpectedly acquired")

    with pytest.raises(OSError) as exc:
        os.fstat(captured["descriptor"])
    assert exc.value.errno == errno.EBADF
