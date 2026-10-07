from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_capture_history_and_comparison_are_wired():
    app=(ROOT/'frontend/src/app/App.tsx').read_text(encoding='utf-8')
    service=(ROOT/'frontend/src/app/services/reportService.ts').read_text(encoding='utf-8')
    comparison=(ROOT/'frontend/src/app/utils/reportComparison.ts').read_text(encoding='utf-8')
    assert 'captureId: string' in service
    assert 'Analysis history' in app and 'Compare selected reports' in app
    assert 'reportItem.captureId === item.captureId' in app
    assert 'Promise.all(compareReportIds.map((id) => loadSavedReport(id)))' in app
    assert 'compareReports' in comparison and 'contextChanges' in comparison
