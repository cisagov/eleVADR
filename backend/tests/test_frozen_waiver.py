from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from backend.regression import synthetic_pcap_corpus as corpus
from backend.regression.frozen_policy import ENV_VAR, allow_missing_frozen


def _entry(name: str, sha: str, builder=None) -> corpus.CorpusEntry:
    return corpus.CorpusEntry(99, name, f"{name}.pcap", f"{name}_context.json", sha, "test", builder)


def _minimal_pcap(path: Path) -> Path:
    # Little-endian PCAP global header with no packets is rejected, so add one packet.
    import struct
    frame = b"\x00" * 14
    path.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(frame), len(frame))
        + frame
    )
    return path


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(corpus, "FIXTURES", tmp_path)
    return tmp_path


def _run(monkeypatch, entries):
    monkeypatch.setattr(corpus, "CORPUS", tuple(entries))
    return corpus.verify_corpus(check_rebuilds=False, verbose=False)


def test_flag_parsing(monkeypatch):
    for value, expected in (("1", True), ("true", True), ("YES", True), ("0", False), ("", False)):
        monkeypatch.setenv(ENV_VAR, value)
        assert allow_missing_frozen() is expected
    monkeypatch.delenv(ENV_VAR)
    assert allow_missing_frozen() is False


def test_missing_frozen_fails_by_default(sandbox, monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    failures = _run(monkeypatch, [_entry("frozen", "0" * 64)])
    assert any("missing" in f for f in failures)


def test_missing_frozen_waived_only_with_flag(sandbox, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "1")
    assert _run(monkeypatch, [_entry("frozen", "0" * 64)]) == []


def test_wrong_hash_still_fails_with_flag(sandbox, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "1")
    _minimal_pcap(sandbox / "frozen.pcap")
    (sandbox / "frozen_context.json").write_text("{}", encoding="utf-8")
    failures = _run(monkeypatch, [_entry("frozen", "0" * 64)])
    assert any("SHA-256 changed" in f for f in failures)


def test_present_frozen_with_correct_hash_passes_with_flag(sandbox, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "1")
    pcap = _minimal_pcap(sandbox / "frozen.pcap")
    (sandbox / "frozen_context.json").write_text("{}", encoding="utf-8")
    sha = hashlib.sha256(pcap.read_bytes()).hexdigest()
    assert _run(monkeypatch, [_entry("frozen", sha)]) == []


def test_missing_generated_capture_is_never_waived(sandbox, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "1")
    failures = _run(monkeypatch, [_entry("generated", "0" * 64, builder=lambda p: p)])
    assert any("missing" in f for f in failures)
