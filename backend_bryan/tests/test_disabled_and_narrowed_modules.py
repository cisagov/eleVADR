from elevadr_modules.models import AnalysisContext
from elevadr_modules.modules.cleartext_credentials import CleartextCredentialsModule
from elevadr_modules.modules.kerberos_asrep_roastable import (
    KerberosAsrepRoastableAccountsModule,
)
from elevadr_modules.modules.netbios_smbv1_exposure import NetbiosSmbv1ExposureModule
from elevadr_modules.modules.smb_signing_ntlmv1 import SmbSigningNtlmv1Module


def test_kerberos_asrep_roastable_is_disabled_by_default():
    assert KerberosAsrepRoastableAccountsModule.metadata.default_enabled is False


def test_smb_signing_ntlmv1_is_disabled_by_default():
    assert SmbSigningNtlmv1Module.metadata.default_enabled is False


def test_netbios_smbv1_exposure_no_longer_detects_smbv1():
    # Explicit SMBv1 version evidence that the old implementation would have flagged.
    context = AnalysisContext(
        smb_cmd=[
            {
                "uid": "u1",
                "source_ip": "10.0.0.5",
                "destination_ip": "203.0.113.9",
                "version": "SMB1",
                "timestamp": 1000,
            }
        ],
    )
    context.metadata["segments"] = [{"name": "ot", "cidr": "10.0.0.0/24", "role": "ot"}]
    result = NetbiosSmbv1ExposureModule().analyze(context)
    assert result.findings == []
    assert "smb_mapping" not in result.evidence["inspected_logs"]
    assert "smb_cmd" not in result.evidence["inspected_logs"]


def test_netbios_smbv1_exposure_still_detects_netbios_cross_segment():
    context = AnalysisContext(
        connections=[
            {
                "uid": "u2",
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.1.5",
                "destination_port": 139,
                "protocol": "tcp",
                "timestamp": 1000,
            }
        ],
    )
    context.metadata["segments"] = [
        {"name": "ot", "cidr": "10.0.0.0/24", "role": "ot"},
        {"name": "it", "cidr": "10.0.1.0/24", "role": "it"},
    ]
    result = NetbiosSmbv1ExposureModule().analyze(context)
    assert len(result.findings) == 1
    assert result.findings[0].services == ["NetBIOS"]


def test_cleartext_credentials_no_longer_detects_telnet():
    context = AnalysisContext(
        telnet=[
            {
                "uid": "u3",
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.6",
                "username": "admin",
                "password": "hunter2",
                "timestamp": 1000,
            }
        ],
    )
    result = CleartextCredentialsModule().analyze(context)
    assert result.findings == []
    assert "telnet" not in result.evidence["inspected_logs"]
    assert "telnet" not in result.evidence["supported_logs"]


def test_cleartext_credentials_still_detects_ftp():
    context = AnalysisContext(
        ftp=[
            {
                "uid": "u4",
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.6",
                "destination_port": 21,
                "username": "admin",
                "password": "hunter2",
                "timestamp": 1000,
            }
        ],
    )
    result = CleartextCredentialsModule().analyze(context)
    assert len(result.findings) == 1
    assert result.findings[0].services == ["FTP"]
