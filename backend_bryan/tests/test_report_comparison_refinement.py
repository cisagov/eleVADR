from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_report_comparison_exposes_analyst_detail():
    app=(ROOT/'frontend/src/app/App.tsx').read_text(encoding='utf-8')
    comparison=(ROOT/'frontend/src/app/utils/reportComparison.ts').read_text(encoding='utf-8')
    assert 'findingDeltas' in comparison and 'severityBefore' in comparison and 'confidenceAfter' in comparison
    assert 'contextDeltas' in comparison and 'moduleDeltas' in comparison and 'formatComparisonValue' in comparison
    assert 'Finding changes (' in app and 'Module configuration changes (' in app
    assert 'Severity:' in app and 'Confidence:' in app
