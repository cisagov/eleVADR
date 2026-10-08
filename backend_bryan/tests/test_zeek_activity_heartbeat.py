import sys
from backend_bryan.runtime.zeek_runtime import _run_zeek_with_activity


def test_zeek_heartbeat_reports_observed_logs(tmp_path):
    script = tmp_path / 'write_logs.py'
    script.write_text("from pathlib import Path\nimport time\nPath('conn.log').write_text('hello')\ntime.sleep(.15)\n")
    events = []
    _run_zeek_with_activity(
        [sys.executable, str(script)], output_path=tmp_path, cwd=tmp_path,
        progress=lambda stage, value, message, detail: events.append((stage, value, message, detail)),
        heartbeat_seconds=.03,
    )
    assert len(events) >= 2
    assert any('conn.log' in (event[3] or '') for event in events)
    assert all(event[1] is None for event in events)
