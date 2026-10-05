from __future__ import annotations

from typing import Any, Callable

from backend_bryan.integration.api_contract import RequestValidationError, validate_api_request
from backend_bryan.integration.http_reference_server import (
    MAX_JSON_REQUEST_BYTES,
    _sanitize_upload_filename,
    _strict_json_loads,
    _validated_content_length,
)


def _base_request() -> dict[str, Any]:
    return {
        "contractVersion": "elevadr.detection-context.analysis.v1",
        "profile": {
            "schemaVersion": 3, "id": "d12", "name": "Input hardening", "segments": [], "assets": [],
            "infrastructure": [], "communicationPairs": [], "allowedHosts": [], "allowedSegmentPairs": [],
            "approvedExternalDestinations": [], "authorizedControlActions": [], "modulePolicies": {},
            "selectedModules": [], "captureScope": {}, "scan": {},
        },
        "logs": {},
    }


def run_cases(verbose: bool = True) -> list[str]:
    failures: list[str] = []
    passed = 0
    def check(label: str, fn: Callable[[], None]) -> None:
        nonlocal passed
        try:
            fn()
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            if verbose: print(f"FAIL  {label} ({type(exc).__name__}: {exc})")
        else:
            passed += 1
            if verbose: print(f"PASS  {label}")

    if verbose:
        print("\n=== 12_input_security: Hostile filenames, size/depth limits, and invalid network values ===")

    check("Traversal-style upload filenames are reduced to a safe basename", lambda: (
        (_sanitize_upload_filename(r"..\\..\\secret\\capture.pcap") == "capture.pcap") or (_ for _ in ()).throw(AssertionError())
    ))
    check("Control characters and empty dot names cannot survive filename normalization", lambda: (
        (_sanitize_upload_filename("../\x00\x01...") == "capture.pcap") or (_ for _ in ()).throw(AssertionError())
    ))

    def content_length_limits() -> None:
        assert _validated_content_length({"Content-Length": "123"}, 1000, "x") == 123
        for bad in ("-1", "not-a-number"):
            try: _validated_content_length({"Content-Length": bad}, 1000, "x")
            except ValueError: pass
            else: raise AssertionError(f"accepted invalid Content-Length {bad}")
        try: _validated_content_length({"Content-Length": str(MAX_JSON_REQUEST_BYTES + 1)}, MAX_JSON_REQUEST_BYTES, "JSON request")
        except ValueError: pass
        else: raise AssertionError("accepted oversized JSON request")
    check("Negative, malformed, and oversized Content-Length values are rejected before reading request bodies", content_length_limits)

    def strict_json_numbers() -> None:
        assert _strict_json_loads(b'{"x":1.5}') == {"x": 1.5}
        for token in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            try: _strict_json_loads(token)
            except ValueError: pass
            else: raise AssertionError(f"accepted non-finite JSON: {token!r}")
    check("NaN and infinity are rejected instead of entering detector policy/data structures", strict_json_numbers)

    def depth_limit() -> None:
        req = _base_request(); value: Any = "leaf"
        for _ in range(45): value = {"x": value}
        req["logs"] = {"dns": [{"nested": value}]}
        try: validate_api_request(req)
        except RequestValidationError as exc: assert exc.errors[0].code == "request_too_deep"
        else: raise AssertionError("deep request accepted")
    check("Deeply nested JSON is rejected at the contract boundary", depth_limit)

    def invalid_cidr() -> None:
        req = _base_request(); req["profile"]["segments"] = [{"name": "bad", "cidr": "10.0.0.999/24", "role": "OT"}]
        try: validate_api_request(req)
        except RequestValidationError as exc: assert any(e.code == "invalid_profile" for e in exc.errors)
        else: raise AssertionError("invalid CIDR accepted")
    check("Invalid segment CIDRs are rejected before policy compilation", invalid_cidr)

    def invalid_asset_ip() -> None:
        req = _base_request(); req["profile"]["assets"] = [{"ip": "999.1.1.1", "source": "user"}]
        try: validate_api_request(req)
        except RequestValidationError as exc: assert any(e.code == "invalid_profile" for e in exc.errors)
        else: raise AssertionError("invalid asset IP accepted")
    check("Invalid authoritative asset IPs are rejected", invalid_asset_ip)

    def invalid_port() -> None:
        req = _base_request(); req["profile"]["communicationPairs"] = [{"sourceIp": "10.0.0.1", "destinationIp": "10.0.0.2", "destinationPort": 70000}]
        try: validate_api_request(req)
        except RequestValidationError as exc: assert any(e.code == "invalid_profile" for e in exc.errors)
        else: raise AssertionError("invalid port accepted")
    check("Communication-pair ports outside 0-65535 are rejected", invalid_port)

    def profile_collection_limit() -> None:
        req = _base_request(); req["profile"]["allowedHosts"] = ["10.0.0.1"] * 100_001
        try: validate_api_request(req)
        except RequestValidationError as exc: assert any(e.code == "collection_too_large" for e in exc.errors)
        else: raise AssertionError("oversized profile collection accepted")
    check("Oversized Detection Context collections are rejected with a structured contract error", profile_collection_limit)

    if verbose:
        print(f"{'FAIL' if failures else 'PASS'}: Dataset 12 verified {passed} input-security cases.")
    return failures


def main() -> int:
    return 1 if run_cases(True) else 0

if __name__ == "__main__":
    raise SystemExit(main())
