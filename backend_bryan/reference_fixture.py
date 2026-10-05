from __future__ import annotations

from backend_bryan.integration.detector_runtime import ensure_detector_package


def representative_profile() -> dict:
    _context, modules, _file = ensure_detector_package()
    return {
        "schemaVersion": 3,
        "id": "pcap-test-profile",
        "name": "PCAP Test Profile",
        "description": "",
        "updatedAt": "2026-09-28T00:00:00Z",
        "selectedModules": list(modules.keys()),
        "scan": {"filesScanned": 0, "recordsParsed": 0, "logTypes": {}, "warnings": []},
        "captureScope": {"internalIcsOnlyExpected": False, "dedicatedOtSensor": True, "ipv4OnlyExpected": False},
        "segments": [],
        "assets": [
            {"id": "a1", "ip": "10.0.0.10", "hostname": "eng", "macAddresses": [], "assetType": "workstation", "role": "it", "services": [], "ports": [], "source": "user", "confidence": "high"},
            {"id": "a2", "ip": "10.0.0.20", "hostname": "plc", "macAddresses": [], "assetType": "plc", "role": "ot", "services": ["modbus"], "ports": [502], "source": "user", "confidence": "high"},
        ],
        "infrastructure": [],
        "communicationPairs": [],
        "allowedHosts": [],
        "allowedSegmentPairs": [],
        "approvedExternalDestinations": [],
        "authorizedControlActions": [],
        "modulePolicies": {},
    }
