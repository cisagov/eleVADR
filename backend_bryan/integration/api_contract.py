"""Versioned API contract for isolated Detection Context analysis.

This module is deliberately framework-free. A production backend can expose the
same request/response contract through Flask, FastAPI, a job queue, or another
transport without changing the semantic boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from backend_bryan.adapters.detection_context_adapter import validate_profile_v3

REQUEST_CONTRACT_VERSION = "elevadr.detection-context.analysis.v1"
RESPONSE_CONTRACT_VERSION = "elevadr.detection-context.analysis-response.v1"
MAX_REQUEST_NESTING_DEPTH = 40
MAX_LOG_ROWS_TOTAL = 500_000
MAX_PROFILE_COLLECTION_ITEMS = 100_000

SUPPORTED_LOG_NAMES = frozenset(
    {
        "connections", "conn", "dns", "http", "quic", "socks", "ftp", "tftp",
        "smtp", "telnet", "login", "ssl", "x509", "ssh", "kerberos", "ntlm",
        "ldap", "ldap_bind", "ldap_search", "smb", "smb_mapping", "smb_files",
        "smb_cmd", "rdp", "ssdp", "upnp", "upnp_igd", "vnc", "modbus", "dnp3",
        "enip", "bacnet", "s7comm", "mms", "iec61850", "dhcp", "ntp", "snmp",
        "arp", "files", "weird",
    }
)


def _validate_json_complexity(value: Any, *, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_REQUEST_NESTING_DEPTH:
        raise RequestValidationError([ContractError("request_too_deep", f"JSON nesting exceeds {MAX_REQUEST_NESTING_DEPTH} levels", path)])
    if isinstance(value, Mapping):
        for key, child in value.items():
            _validate_json_complexity(child, path=f"{path}.{key}", depth=depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json_complexity(child, path=f"{path}[{index}]", depth=depth + 1)


def _validate_profile_collection_sizes(profile: Mapping[str, Any]) -> None:
    for key in (
        "segments", "assets", "infrastructure", "communicationPairs", "allowedHosts",
        "allowedSegmentPairs", "approvedExternalDestinations", "authorizedControlActions", "selectedModules",
    ):
        value = profile.get(key)
        if isinstance(value, list) and len(value) > MAX_PROFILE_COLLECTION_ITEMS:
            raise RequestValidationError([ContractError("collection_too_large", f"profile.{key} exceeds {MAX_PROFILE_COLLECTION_ITEMS} items", f"profile.{key}")])


@dataclass(slots=True, frozen=True)
class ContractError:
    code: str
    message: str
    path: str | None = None
    module_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.path is not None:
            result["path"] = self.path
        if self.module_id is not None:
            result["moduleId"] = self.module_id
        return result


class RequestValidationError(ValueError):
    def __init__(self, errors: list[ContractError]):
        self.errors = errors
        super().__init__("; ".join(error.message for error in errors))


def _validate_logs(logs: Any) -> dict[str, list[dict[str, Any]]]:
    if logs is None:
        return {}
    if not isinstance(logs, Mapping):
        raise RequestValidationError(
            [ContractError("invalid_type", "logs must be an object", "logs")]
        )

    normalized: dict[str, list[dict[str, Any]]] = {}
    errors: list[ContractError] = []
    total_rows = 0
    for raw_name, rows in logs.items():
        name = str(raw_name)
        if name not in SUPPORTED_LOG_NAMES:
            errors.append(
                ContractError(
                    "unsupported_log",
                    f"Unsupported Zeek log name: {name}",
                    f"logs.{name}",
                )
            )
            continue
        if not isinstance(rows, list):
            errors.append(
                ContractError("invalid_type", "log value must be an array", f"logs.{name}")
            )
            continue
        total_rows += len(rows)
        if total_rows > MAX_LOG_ROWS_TOTAL:
            errors.append(ContractError("too_many_log_rows", f"logs exceed {MAX_LOG_ROWS_TOTAL} total rows", "logs"))
            break
        bad_index = next((idx for idx, row in enumerate(rows) if not isinstance(row, Mapping)), None)
        if bad_index is not None:
            errors.append(
                ContractError(
                    "invalid_type",
                    "each log row must be an object",
                    f"logs.{name}[{bad_index}]",
                )
            )
            continue
        target = "connections" if name == "conn" else name
        normalized[target] = [dict(row) for row in rows]

    if errors:
        raise RequestValidationError(errors)
    return normalized


def validate_api_request(request: Any) -> tuple[Mapping[str, Any], dict[str, list[dict[str, Any]]]]:
    errors: list[ContractError] = []
    if not isinstance(request, Mapping):
        raise RequestValidationError(
            [ContractError("invalid_type", "request must be a JSON object", "$")]
        )

    _validate_json_complexity(request)

    allowed_keys = {"contractVersion", "profile", "logs"}
    extra_keys = sorted(str(key) for key in request.keys() if key not in allowed_keys)
    for key in extra_keys:
        errors.append(
            ContractError(
                "unexpected_field",
                f"Unexpected request field: {key}",
                key,
            )
        )

    if request.get("contractVersion") != REQUEST_CONTRACT_VERSION:
        errors.append(
            ContractError(
                "unsupported_contract_version",
                f"contractVersion must be {REQUEST_CONTRACT_VERSION}",
                "contractVersion",
            )
        )

    profile = request.get("profile")
    if not isinstance(profile, Mapping):
        errors.append(
            ContractError("invalid_type", "profile must be a Detection Context object", "profile")
        )
    else:
        try:
            validate_profile_v3(profile)
        except (TypeError, ValueError) as exc:
            errors.append(ContractError("invalid_profile", str(exc), "profile"))
        else:
            try:
                _validate_profile_collection_sizes(profile)
            except RequestValidationError as exc:
                errors.extend(exc.errors)

    if errors:
        raise RequestValidationError(errors)

    logs = _validate_logs(request.get("logs"))
    return profile, logs  # type: ignore[return-value]


def error_response(errors: list[ContractError]) -> dict[str, Any]:
    return {
        "contractVersion": RESPONSE_CONTRACT_VERSION,
        "status": "failed",
        "summary": {
            "requestedModules": 0,
            "completedModules": 0,
            "failedModules": 0,
            "findingCount": 0,
        },
        "moduleResults": [],
        "errors": [error.to_dict() for error in errors],
    }
