from __future__ import annotations

from unittest.mock import patch

from backend_bryan.integration.api_contract import REQUEST_CONTRACT_VERSION, RESPONSE_CONTRACT_VERSION
from backend_bryan.integration.http_reference_server import health_payload


def test_health_payload_exposes_release_diagnostics_without_requiring_zeek() -> None:
    with patch("backend_bryan.runtime.zeek_runtime.describe_zeek_runtime", return_value="unavailable (test)"):
        payload = health_payload()
    assert payload["status"] == "ok"
    assert payload["detectorModules"] == 75
    assert payload["requestContractVersion"] == REQUEST_CONTRACT_VERSION
    assert payload["responseContractVersion"] == RESPONSE_CONTRACT_VERSION
    assert payload["zeekRuntime"] == "unavailable (test)"
    assert payload["evidenceTtlSeconds"] > 0
