from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_stage3_report_persistence_contract_is_wired() -> None:
    server = (ROOT / "backend_bryan/integration/http_reference_server.py").read_text(encoding="utf-8")
    app = (ROOT / "frontend/src/app/App.tsx").read_text(encoding="utf-8")
    service = (ROOT / "frontend/src/app/services/reportService.ts").read_text(encoding="utf-8")
    assert 'REPORTS_PATH = "/api/v1/reports"' in server
    assert "_REPORT_STORE.save(owner_id, owner_username, report, filename, capture_id=capture_id)" in server
    assert '"ownerId": principal.user_id if principal and principal.authenticated else None' in server
    assert "listSavedReports" in app and "openSavedReport" in app and "removeSavedReport" in app
    assert "authenticatedFetch" in service and "/api/v1/reports" in service
