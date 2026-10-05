from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from elevadr_modules.models import AnalysisContext
from elevadr_modules.zeek.parser import load_zeek_directory


# Zeek intentionally disables password capture for FTP and HTTP Basic Auth by default.
# The standalone module harness enables it when it generates logs from a PCAP so the
# cleartext-credential module has the evidence it needs. Generated module output still
# redacts passwords before returning or writing JSON.
PASSWORD_CAPTURE_OPTIONS = (
    "FTP::default_capture_password=T",
    "HTTP::default_capture_password=T",
    'FTP::logged_commands+={"PASS"}',
)


def run_zeek_on_pcap(
    pcap: str | Path,
    output_dir: str | Path | None = None,
    *,
    zeek_binary: str = "zeek",
) -> tuple[AnalysisContext, Path]:
    pcap_path = Path(pcap).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(pcap_path)
    if shutil.which(zeek_binary) is None:
        raise RuntimeError(
            f"Zeek executable '{zeek_binary}' was not found on PATH. "
            "Install Zeek or run modules against existing Zeek logs."
        )

    if output_dir is None:
        output_path = Path(tempfile.mkdtemp(prefix="elevadr-zeek-"))
    else:
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [zeek_binary, "-r", str(pcap_path), *PASSWORD_CAPTURE_OPTIONS],
        cwd=output_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return load_zeek_directory(output_path), output_path
