"""Migrate port_risk.json into port_risk_v2.json.

Adds three new fields to each entry:
  - risk_basis:           "Observed" | "Credible" | null
  - environment_exposure: "External" | "Cross-Zone" | "Internal" | null
  - protocol_posture:     "Inherently Risky" | "Conditionally Risky" | null

Default inference logic is based on existing risk/information categories and
known service characteristics. All fields default to null when no confident
inference can be made - these should be reviewed and populated from VM reports.
"""

# Standard Python Libraries
import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

# Risk categories that strongly indicate real-world observed exploitation
_OBSERVED_RISK_CATEGORIES = {
    "C2 Channel",
    "Data Exfiltration",
    "Lateral Movement",
    "Amplification/Reflection",
    "Rogue Services",
}

# Risk categories that indicate conditional/credible risk
_CREDIBLE_RISK_CATEGORIES = {
    "Remote Access",
    "File Transfer",
    "File Sharing",
    "Legacy Protocol",
    "Unencrypted Protocol",
    "Out-of-Band Access",
    "Third-Party Remote Support",
    "Messaging Protocol",
    "Network Discovery",
    "Web Communication",
    "Database Services",
}

# Services that are inherently risky regardless of environment
_INHERENTLY_RISKY_SERVICES = {
    "telnet",
    "ftp",
    "rsh",
    "rlogin",
    "rexec",
    "tftp",
    "finger",
    "chargen",
    "echo",
    "discard",
    "daytime",
    "netbios-ssn",
    "netbios-ns",
    "netbios-dgm",
}

# Information categories that indicate the service is inherently risky
_INHERENTLY_RISKY_INFO_CATEGORIES = {
    "Legacy Protocol",
}

# Risk categories that indicate external exposure is likely
_EXTERNAL_EXPOSURE_RISK_CATEGORIES = {
    "C2 Channel",
    "Data Exfiltration",
    "Amplification/Reflection",
    "Web Communication",
}

# Information categories that suggest cross-zone traversal risk
_CROSS_ZONE_INFO_CATEGORIES = {
    "Industrial Protocol",
    "Remote Access",
    "VPN",
    "Out-of-Band Access",
}


def infer_risk_basis(
    risk_categories: list | None,
    information_categories: list | None,
) -> str | None:
    """Infer risk_basis from existing category data.

    Returns "Observed" if the service has categories tied to active exploitation,
    "Credible" if it has known-risky-but-conditional categories, else null.
    """
    if not risk_categories and not information_categories:
        return None

    cats = set(risk_categories or [])

    if cats & _OBSERVED_RISK_CATEGORIES:
        return "Observed"

    if cats & _CREDIBLE_RISK_CATEGORIES:
        return "Credible"

    return None


def infer_environment_exposure(
    risk_categories: list | None,
    information_categories: list | None,
    service_name: str | None,
) -> str | None:
    """Infer environment_exposure from category data and service name.

    Returns "External", "Cross-Zone", or "Internal". Defaults to null when
    no confident inference can be made.
    """
    if not risk_categories and not information_categories:
        return None

    risk_cats = set(risk_categories or [])
    info_cats = set(information_categories or [])

    if risk_cats & _EXTERNAL_EXPOSURE_RISK_CATEGORIES:
        return "External"

    if info_cats & _CROSS_ZONE_INFO_CATEGORIES:
        return "Cross-Zone"

    # Industrial protocols that cross OT/IT boundaries are cross-zone by nature
    if "Industrial Protocol" in info_cats:
        return "Cross-Zone"

    return None


def infer_protocol_posture(
    risk_categories: list | None,
    information_categories: list | None,
    service_name: str | None,
) -> str | None:
    """Infer protocol_posture from category data and service name.

    Returns "Inherently Risky" for clear-text or historically exploited protocols,
    "Conditionally Risky" for protocols that are safe when hardened, else null.
    """
    if not risk_categories and not information_categories:
        return None

    risk_cats = set(risk_categories or [])
    info_cats = set(information_categories or [])
    svc = (service_name or "").lower()

    # Explicit legacy/unencrypted combination is inherently risky
    has_legacy = "Legacy Protocol" in risk_cats
    has_unencrypted = "Unencrypted Protocol" in risk_cats

    if has_legacy and has_unencrypted:
        return "Inherently Risky"

    if svc in _INHERENTLY_RISKY_SERVICES:
        return "Inherently Risky"

    # C2 and data exfil channels are inherently risky
    if {"C2 Channel", "Data Exfiltration"} & risk_cats:
        return "Inherently Risky"

    # Unencrypted alone or remote access is conditionally risky
    if has_unencrypted or "Remote Access" in risk_cats:
        return "Conditionally Risky"

    # Industrial protocols are conditionally risky (safe within zone, risky across)
    if "Industrial Protocol" in info_cats:
        return "Conditionally Risky"

    # Secure protocols with caveats
    for info_cat in info_cats:
        if info_cat.startswith("Secure Protocol"):
            return "Conditionally Risky"

    return None


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


def migrate(input_path: Path, output_path: Path) -> None:
    """Load port_risk.json, enrich each entry, write port_risk_v2.json."""
    with open(input_path) as f:
        port_risk: dict = json.load(f)

    migrated: dict = {}

    for port_key, entry in port_risk.items():
        if entry is None:
            # Some entries are explicitly null in the source file
            migrated[port_key] = {
                "service": None,
                "description": None,
                "information_categories": None,
                "risk_categories": None,
                "risk_basis": None,
                "environment_exposure": None,
                "protocol_posture": None,
            }
            continue

        risk_cats = entry.get("risk_categories")
        info_cats = entry.get("information_categories")
        service_name = entry.get("service")

        migrated[port_key] = {
            # Preserve all existing fields
            "service": service_name,
            "description": entry.get("description"),
            "information_categories": info_cats,
            "risk_categories": risk_cats,
            # New fields
            "risk_basis": infer_risk_basis(risk_cats, info_cats),
            "environment_exposure": infer_environment_exposure(risk_cats, info_cats, service_name),
            "protocol_posture": infer_protocol_posture(risk_cats, info_cats, service_name),
        }

    with open(output_path, "w") as f:
        json.dump(migrated, f, indent=4)

    # Print a summary so the operator knows what was inferred vs left null
    total = len(migrated)
    basis_null = sum(1 for v in migrated.values() if v.get("risk_basis") is None)
    exposure_null = sum(1 for v in migrated.values() if v.get("environment_exposure") is None)
    posture_null = sum(1 for v in migrated.values() if v.get("protocol_posture") is None)

    print(f"Migrated {total} entries to {output_path}")
    print(f"  risk_basis       - inferred: {total - basis_null:>4}, null: {basis_null}")
    print(f"  environment_exposure - inferred: {total - exposure_null:>4}, null: {exposure_null}")
    print(f"  protocol_posture - inferred: {total - posture_null:>4}, null: {posture_null}")
    print("Review null entries and populate from VM reports.")


if __name__ == "__main__":
    base = Path(__file__).parent
    migrate(
        input_path=base / "port_risk.json",
        output_path=base / "port_risk_v2.json",
    )
