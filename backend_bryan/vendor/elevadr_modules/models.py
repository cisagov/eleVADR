from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class AnalysisContext:
    """Normalized Zeek data shared by all analysis modules."""

    connections: list[dict[str, Any]] = field(default_factory=list)
    dns: list[dict[str, Any]] = field(default_factory=list)
    http: list[dict[str, Any]] = field(default_factory=list)
    quic: list[dict[str, Any]] = field(default_factory=list)
    socks: list[dict[str, Any]] = field(default_factory=list)
    ftp: list[dict[str, Any]] = field(default_factory=list)
    tftp: list[dict[str, Any]] = field(default_factory=list)
    smtp: list[dict[str, Any]] = field(default_factory=list)
    telnet: list[dict[str, Any]] = field(default_factory=list)
    login: list[dict[str, Any]] = field(default_factory=list)
    ssl: list[dict[str, Any]] = field(default_factory=list)
    x509: list[dict[str, Any]] = field(default_factory=list)
    ssh: list[dict[str, Any]] = field(default_factory=list)
    kerberos: list[dict[str, Any]] = field(default_factory=list)
    ntlm: list[dict[str, Any]] = field(default_factory=list)
    ldap: list[dict[str, Any]] = field(default_factory=list)
    ldap_bind: list[dict[str, Any]] = field(default_factory=list)
    ldap_search: list[dict[str, Any]] = field(default_factory=list)
    smb: list[dict[str, Any]] = field(default_factory=list)
    smb_mapping: list[dict[str, Any]] = field(default_factory=list)
    smb_files: list[dict[str, Any]] = field(default_factory=list)
    smb_cmd: list[dict[str, Any]] = field(default_factory=list)
    rdp: list[dict[str, Any]] = field(default_factory=list)
    ssdp: list[dict[str, Any]] = field(default_factory=list)
    upnp: list[dict[str, Any]] = field(default_factory=list)
    upnp_igd: list[dict[str, Any]] = field(default_factory=list)
    vnc: list[dict[str, Any]] = field(default_factory=list)
    modbus: list[dict[str, Any]] = field(default_factory=list)
    dnp3: list[dict[str, Any]] = field(default_factory=list)
    enip: list[dict[str, Any]] = field(default_factory=list)
    bacnet: list[dict[str, Any]] = field(default_factory=list)
    s7comm: list[dict[str, Any]] = field(default_factory=list)
    mms: list[dict[str, Any]] = field(default_factory=list)
    iec61850: list[dict[str, Any]] = field(default_factory=list)
    dhcp: list[dict[str, Any]] = field(default_factory=list)
    ntp: list[dict[str, Any]] = field(default_factory=list)
    snmp: list[dict[str, Any]] = field(default_factory=list)
    arp: list[dict[str, Any]] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)
    weird: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def log(self, name: str) -> list[dict[str, Any]]:
        aliases = {
            "conn": "connections",
            "connections": "connections",
            "dns": "dns",
            "http": "http",
            "quic": "quic",
            "socks": "socks",
            "ftp": "ftp",
            "tftp": "tftp",
            "smtp": "smtp",
            "telnet": "telnet",
            "login": "login",
            "ssl": "ssl",
            "x509": "x509",
            "ssh": "ssh",
            "kerberos": "kerberos",
            "ntlm": "ntlm",
            "ldap": "ldap",
            "ldap_bind": "ldap_bind",
            "ldap_search": "ldap_search",
            "smb": "smb",
            "smb_mapping": "smb_mapping",
            "smb_files": "smb_files",
            "smb_cmd": "smb_cmd",
            "rdp": "rdp",
            "ssdp": "ssdp",
            "upnp": "upnp",
            "upnp_igd": "upnp_igd",
            "vnc": "vnc",
            "modbus": "modbus",
            "dnp3": "dnp3",
            "enip": "enip",
            "bacnet": "bacnet",
            "s7comm": "s7comm",
            "mms": "mms",
            "iec61850": "iec61850",
            "dhcp": "dhcp",
            "ntp": "ntp",
            "snmp": "snmp",
            "arp": "arp",
            "files": "files",
            "weird": "weird",
        }
        attr = aliases.get(name, name)
        value = getattr(self, attr, None)
        return value if isinstance(value, list) else []


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    summary: str
    confidence: str
    detection_basis: str
    devices: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    connection_pairs: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    subnets: list[str] = field(default_factory=list)
    timestamps: list[float | str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        severity = self.severity.lower().strip()
        confidence = self.confidence.lower().strip()
        basis = self.detection_basis.lower().strip()
        if severity not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError(f"Unsupported finding severity: {self.severity}")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError(f"Unsupported finding confidence: {self.confidence}")
        if basis not in {"port", "zeek_service", "protocol_log", "derived", "heuristic"}:
            raise ValueError(f"Unsupported finding detection_basis: {self.detection_basis}")
        self.severity = severity
        self.confidence = confidence
        self.detection_basis = basis

        # Keep the common provenance fields mirrored in metadata so downstream
        # consumers that inspect metadata get the same values as the top level.
        self.metadata.setdefault("confidence", self.confidence)
        self.metadata.setdefault("detection_basis", self.detection_basis)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ModuleResult:
    module_id: str
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "findings": [finding.to_dict() for finding in self.findings],
            "metrics": self.metrics,
            "evidence": self.evidence,
            "warnings": self.warnings,
        }
