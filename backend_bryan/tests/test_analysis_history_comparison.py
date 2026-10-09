from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_capture_history_and_comparison_are_wired():
    app=(ROOT/'frontend/src/app/App.tsx').read_text(encoding='utf-8')
    service=(ROOT/'frontend/src/app/services/reportService.ts').read_text(encoding='utf-8')
    comparison=(ROOT/'frontend/src/app/utils/reportComparison.ts').read_text(encoding='utf-8')
    assert 'captureId: string' in service
    assert 'analysisCaptureGroups' in app and 'Compare analyses' in app and 'setHistoryCaptureId' in app
    assert 'group.analyses' in app and 'group.capture' in app
    assert 'compareReportIds.map((id) => loadSavedReport(id))' in app
    assert 'setReportComparison(compareReports(left, right))' in app
    assert 'compareReports' in comparison and 'contextChanges' in comparison
