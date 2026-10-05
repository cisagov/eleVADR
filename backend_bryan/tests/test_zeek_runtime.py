from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from backend_bryan.runtime.zeek_runtime import (
    DEFAULT_ZEEK_DOCKER_IMAGE,
    resolve_zeek_runtime,
)


def test_explicit_zeek_command_has_highest_priority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "zeek-custom"
    fake.write_text("fake")
    monkeypatch.setenv("ELEVADR_ZEEK_COMMAND", str(fake))
    with patch("backend_bryan.runtime.zeek_runtime.shutil.which", return_value="/usr/bin/docker"):
        runtime = resolve_zeek_runtime()
    assert runtime.kind == "native"
    assert runtime.command == (str(fake),)


def test_native_zeek_precedes_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ELEVADR_ZEEK_COMMAND", raising=False)

    def which(name: str) -> str | None:
        return "/usr/bin/zeek" if name == "zeek" else "/usr/bin/docker"

    with patch("backend_bryan.runtime.zeek_runtime.shutil.which", side_effect=which):
        runtime = resolve_zeek_runtime()
    assert runtime.kind == "native"
    assert runtime.command == ("/usr/bin/zeek",)


def test_docker_is_fallback_and_image_is_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ELEVADR_ZEEK_COMMAND", raising=False)
    monkeypatch.delenv("ELEVADR_ZEEK_DOCKER_IMAGE", raising=False)

    def which(name: str) -> str | None:
        return None if name == "zeek" else "/usr/bin/docker" if name == "docker" else None

    with patch("backend_bryan.runtime.zeek_runtime.shutil.which", side_effect=which):
        runtime = resolve_zeek_runtime()
    assert runtime.kind == "docker"
    assert runtime.docker_image == DEFAULT_ZEEK_DOCKER_IMAGE


def test_docker_image_can_be_overridden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ELEVADR_ZEEK_COMMAND", raising=False)
    monkeypatch.setenv("ELEVADR_ZEEK_DOCKER_IMAGE", "zeek/zeek:custom")

    def which(name: str) -> str | None:
        return "/usr/bin/docker" if name == "docker" else None

    with patch("backend_bryan.runtime.zeek_runtime.shutil.which", side_effect=which):
        runtime = resolve_zeek_runtime()
    assert runtime.kind == "docker"
    assert runtime.docker_image == "zeek/zeek:custom"


def test_clear_error_when_no_runtime_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ELEVADR_ZEEK_COMMAND", raising=False)
    with patch("backend_bryan.runtime.zeek_runtime.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="Zeek runtime unavailable"):
            resolve_zeek_runtime()


def test_docker_pull_reports_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    from io import StringIO
    from types import SimpleNamespace
    from backend_bryan.runtime.zeek_runtime import ZeekRuntime, _pull_docker_image

    runtime = ZeekRuntime(kind="docker", command=("docker",), docker_image="zeek/zeek:9.0.0")
    events: list[tuple[str, int | None, str, str | None]] = []
    fake_stdout = StringIO(
        "111111aaaaaa: Downloading 10MB/100MB\n"
        "222222bbbbbb: Pull complete\n"
        "111111aaaaaa: Pull complete\n"
        "Digest: sha256:example\n"
    )
    process = SimpleNamespace(stdout=fake_stdout, wait=lambda: 0)
    monkeypatch.setattr("backend_bryan.runtime.zeek_runtime.subprocess.Popen", lambda *args, **kwargs: process)

    _pull_docker_image(runtime, lambda stage, value, message, detail: events.append((stage, value, message, detail)))

    assert events[0][0] == "docker-pull"
    assert any(event[1] is not None and event[1] > 5 for event in events if event[0] == "docker-pull")
    assert events[-1][0] == "docker-ready"
    assert events[-1][1] == 30


def test_elevadr_runtime_policy_enables_arp_logging() -> None:
    from backend_bryan.runtime.zeek_runtime import RUNTIME_POLICY

    text = RUNTIME_POLICY.read_text(encoding="utf-8")
    assert "PacketAnalyzer::ANALYZER_ARP" in text
    assert '$path="arp"' in text
    assert "event arp_request" in text
    assert "event arp_reply" in text
