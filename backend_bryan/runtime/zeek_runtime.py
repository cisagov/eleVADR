"""Resolve and execute Zeek for the isolated eleVADR PCAP workflows.

Runtime priority:
1. ELEVADR_ZEEK_COMMAND (explicit native command/executable)
2. Native ``zeek`` available on PATH
3. Docker Desktop / Docker Engine using a pinned official Zeek image

The Docker runtime reports preparation and image-pull status through an optional
progress callback so the frontend can distinguish downloading from Zeek analysis.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from backend_bryan.integration.detector_runtime import ensure_detector_package

DEFAULT_ZEEK_DOCKER_IMAGE = "zeek/zeek:9.0.0"
RUNTIME_POLICY = Path(__file__).with_name("elevadr_runtime.zeek")

PASSWORD_CAPTURE_OPTIONS: tuple[str, ...] = (
    "FTP::default_capture_password=T",
    "HTTP::default_capture_password=T",
    'FTP::logged_commands+={"PASS"}',
)
ProgressCallback = Callable[[str, int | None, str, str | None], None]


@dataclass(frozen=True)
class ZeekRuntime:
    kind: str
    command: tuple[str, ...]
    docker_image: str | None = None

    @property
    def label(self) -> str:
        if self.kind == "docker":
            return f"Docker ({self.docker_image})"
        return " ".join(self.command)


def _emit(progress: ProgressCallback | None, stage: str, value: int | None, message: str, detail: str | None = None) -> None:
    if progress is not None:
        progress(stage, value, message, detail)


def _split_command(value: str) -> tuple[str, ...]:
    candidate = Path(value.strip().strip('"'))
    if candidate.exists():
        return (str(candidate),)

    # ``shlex.split(..., posix=False)`` is needed on Windows so backslashes in
    # native paths are preserved, but it also leaves surrounding quotes on each
    # token.  Strip one matching quote layer so an explicit command such as
    # ``"C:\\Program Files\\Python312\\python.exe" "C:\\tmp\\fake_zeek"``
    # resolves to an actual executable plus arguments rather than a filename that
    # literally contains quote characters.
    parts = shlex.split(value, posix=os.name != "nt")
    normalized: list[str] = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in {"\"", "'"}:
            part = part[1:-1]
        normalized.append(part)
    return tuple(normalized)


def _command_available(command: Sequence[str]) -> bool:
    if not command:
        return False
    executable = command[0]
    candidate = Path(executable)
    return candidate.exists() or shutil.which(executable) is not None


def resolve_zeek_runtime() -> ZeekRuntime:
    explicit = os.environ.get("ELEVADR_ZEEK_COMMAND", "").strip()
    if explicit:
        command = _split_command(explicit)
        if not _command_available(command):
            raise RuntimeError(
                f"ELEVADR_ZEEK_COMMAND is set to '{explicit}', but that executable could not be found."
            )
        return ZeekRuntime(kind="native", command=command)

    native = shutil.which("zeek")
    if native:
        return ZeekRuntime(kind="native", command=(native,))

    docker = shutil.which("docker")
    if docker:
        image = os.environ.get("ELEVADR_ZEEK_DOCKER_IMAGE", DEFAULT_ZEEK_DOCKER_IMAGE).strip() or DEFAULT_ZEEK_DOCKER_IMAGE
        return ZeekRuntime(kind="docker", command=(docker,), docker_image=image)

    raise RuntimeError(
        "Zeek runtime unavailable. Install Zeek on PATH, set ELEVADR_ZEEK_COMMAND, "
        "or install/start Docker Desktop so eleVADR can use the pinned official Zeek image "
        f"{DEFAULT_ZEEK_DOCKER_IMAGE}."
    )




def zeek_evidence_signature() -> dict[str, str]:
    """Return stable audit metadata for the Zeek extraction configuration."""
    runtime = resolve_zeek_runtime()
    policy_sha256 = hashlib.sha256(RUNTIME_POLICY.read_bytes()).hexdigest() if RUNTIME_POLICY.exists() else "missing"
    return {
        "zeek_runtime": runtime.label,
        "zeek_policy_sha256": policy_sha256,
        "zeek_docker_image": runtime.docker_image or "",
    }

def describe_zeek_runtime() -> str:
    try:
        runtime = resolve_zeek_runtime()
    except RuntimeError as exc:
        return f"unavailable ({exc})"
    return runtime.label


def _run_checked(command: list[str], *, cwd: Path | None = None) -> None:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Zeek runtime command could not be started: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        detail = stderr or stdout or f"exit code {exc.returncode}"
        raise RuntimeError(f"Zeek execution failed: {detail}") from exc
    if completed.returncode != 0:
        raise RuntimeError(f"Zeek execution failed with exit code {completed.returncode}")



def _run_zeek_with_activity(
    command: list[str], *, output_path: Path, progress: ProgressCallback | None,
    cwd: Path | None = None, runtime_label: str = "Zeek",
    heartbeat_seconds: float = 3.0,
) -> None:
    """Report observed log activity without inventing packet-based completion percentages."""
    started = time.monotonic()
    # A file avoids pipe deadlocks for verbose Zeek executions.
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as output:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Zeek runtime command could not be started: {command[0]}") from exc
        try:
            while process.poll() is None:
                elapsed = int(time.monotonic() - started)
                logs = sorted(output_path.glob("*.log"))
                nonempty = [(log.name, log.stat().st_size) for log in logs if log.is_file()]
                bytes_written = sum(size for _, size in nonempty)
                names = ", ".join(name for name, _ in nonempty[:5])
                detail = (
                    f"{runtime_label} | Elapsed {elapsed // 60}m {elapsed % 60:02d}s | "
                    f"{len(nonempty)} logs, {bytes_written / (1024 * 1024):.1f} MiB written"
                    + (f" | Logs: {names}" if names else " | Waiting for Zeek to flush logs")
                )
                _emit(progress, "zeek-running", None, "Zeek processing capture (still active)…", detail)
                process.wait(timeout=heartbeat_seconds) if process.poll() is not None else time.sleep(heartbeat_seconds)
        except BaseException:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise
        if process.returncode != 0:
            output.seek(0)
            detail = output.read()[-4000:].strip() or f"exit code {process.returncode}"
            raise RuntimeError(f"Zeek execution failed: {detail}")
    _emit(progress, "zeek-running", None, "Zeek finished processing capture; preparing logs…", f"Elapsed {int(time.monotonic() - started)}s")


def _docker_image_available(runtime: ZeekRuntime) -> bool:
    assert runtime.docker_image
    completed = subprocess.run(
        [runtime.command[0], "image", "inspect", runtime.docker_image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def _pull_docker_image(runtime: ZeekRuntime, progress: ProgressCallback | None) -> None:
    assert runtime.docker_image
    _emit(progress, "docker-pull", 5, f"Downloading Zeek Docker image {runtime.docker_image}…", "Starting Docker image pull")
    try:
        process = subprocess.Popen(
            [runtime.command[0], "pull", runtime.docker_image],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker could not be started. Install or start Docker Desktop and retry.") from exc

    layers: dict[str, str] = {}
    last_line = ""
    if process.stdout is not None:
        for raw_line in process.stdout:
            line = raw_line.strip()
            if not line:
                continue
            last_line = line
            # Classic Docker CLI output starts each layer line with a 12-char layer id.
            match = re.match(r"^([0-9a-f]{6,64}):\s+(.+)$", line, re.IGNORECASE)
            if match:
                layer, status = match.groups()
                layers[layer] = status
                completed = sum(
                    1
                    for item in layers.values()
                    if any(token in item.lower() for token in ("pull complete", "already exists", "download complete"))
                )
                total = max(len(layers), 1)
                approx = min(29, 5 + int(24 * completed / total))
                _emit(
                    progress,
                    "docker-pull",
                    approx,
                    f"Downloading Zeek Docker image {runtime.docker_image}…",
                    f"{completed}/{total} observed layers complete · {line}",
                )
            else:
                _emit(progress, "docker-pull", None, f"Downloading Zeek Docker image {runtime.docker_image}…", line)

    return_code = process.wait()
    if return_code != 0:
        detail = last_line or f"docker pull exited with code {return_code}"
        raise RuntimeError(f"Unable to download Zeek Docker image {runtime.docker_image}: {detail}")
    _emit(progress, "docker-ready", 30, "Zeek Docker image is ready.", runtime.docker_image)


def _ensure_docker_image(runtime: ZeekRuntime, progress: ProgressCallback | None) -> None:
    assert runtime.docker_image
    _emit(progress, "docker-check", 3, "Checking Zeek Docker runtime…", runtime.docker_image)
    try:
        if _docker_image_available(runtime):
            _emit(progress, "docker-ready", 30, "Zeek Docker image is already available.", runtime.docker_image)
            return
    except OSError as exc:
        raise RuntimeError("Docker could not be started. Start Docker Desktop and retry.") from exc
    _pull_docker_image(runtime, progress)


def _runtime_policy_copy(output_path: Path) -> Path:
    if not RUNTIME_POLICY.exists():
        raise RuntimeError(f"eleVADR Zeek runtime policy is missing: {RUNTIME_POLICY}")
    target = output_path / "elevadr_runtime.zeek"
    shutil.copyfile(RUNTIME_POLICY, target)
    return target


def _run_native(runtime: ZeekRuntime, pcap_path: Path, output_path: Path, progress: ProgressCallback | None) -> None:
    policy_path = _runtime_policy_copy(output_path)
    _emit(progress, "zeek-running", None, "Analyzing PCAP with Zeek…", pcap_path.name)
    _run_zeek_with_activity(
        [*runtime.command, "-r", str(pcap_path), *PASSWORD_CAPTURE_OPTIONS, str(policy_path)],
        output_path=output_path, progress=progress, cwd=output_path, runtime_label=runtime.label,
    )


def _run_docker(runtime: ZeekRuntime, pcap_path: Path, output_path: Path, progress: ProgressCallback | None) -> None:
    assert runtime.docker_image
    _ensure_docker_image(runtime, progress)
    input_dir = pcap_path.parent.resolve()
    output_dir = output_path.resolve()
    policy_path = _runtime_policy_copy(output_path)
    command = [
        runtime.command[0],
        "run",
        "--rm",
        "-v",
        f"{input_dir}:/input:ro",
        "-v",
        f"{output_dir}:/output",
        "-w",
        "/output",
        runtime.docker_image,
        "zeek",
        "-r",
        f"/input/{pcap_path.name}",
        *PASSWORD_CAPTURE_OPTIONS,
        f"/output/{policy_path.name}",
    ]
    _emit(progress, "zeek-running", None, "Analyzing PCAP with Zeek…", f"Docker image: {runtime.docker_image}")
    try:
        _run_zeek_with_activity(command, output_path=output_path, progress=progress, runtime_label=runtime.label)
    except RuntimeError as exc:
        message = str(exc)
        if "docker daemon" in message.lower() or "cannot connect" in message.lower():
            raise RuntimeError(
                "Docker was found but is not running. Start Docker Desktop and retry PCAP analysis."
            ) from exc
        raise


def run_zeek_on_pcap(
    pcap: str | Path,
    output_dir: str | Path | None = None,
    *,
    progress: ProgressCallback | None = None,
) -> tuple[object, Path]:
    """Run Zeek using the resolved runtime and parse the resulting Zeek directory."""
    ensure_detector_package()
    from elevadr_modules.zeek.parser import load_zeek_directory

    pcap_path = Path(pcap).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(pcap_path)

    if output_dir is None:
        output_path = Path(tempfile.mkdtemp(prefix="elevadr-zeek-"))
    else:
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)

    _emit(progress, "preparing", 1, "Preparing packet capture…", pcap_path.name)
    runtime = resolve_zeek_runtime()
    if runtime.kind == "docker":
        _run_docker(runtime, pcap_path, output_path, progress)
    else:
        _emit(progress, "runtime-ready", 30, "Native Zeek runtime is ready.", runtime.label)
        _run_native(runtime, pcap_path, output_path, progress)

    _emit(progress, "parsing-zeek", 82, "Parsing Zeek logs…", str(output_path))
    context = load_zeek_directory(output_path)
    return context, output_path
