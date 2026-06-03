"""Tests for API and CLI entrypoints in app.main."""

# Standard Python Libraries
import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import ANY, MagicMock, Mock, patch

import pandas as pd
import pytest

# Third-Party Libraries
from fastapi.testclient import TestClient

# cisagov Libraries
# Assuming the main app is in src/app/main.py
# We need to adjust the import path based on how pytest runs
# For now, let's assume it can be imported directly if tests are run from the project root
# or if the src/app directory is added to PYTHONPATH.
# If not, we might need to adjust sys.path or use a different import strategy.
from src.app.main import (
    _emit,
    _progress_queues,
    app,
    logger,
    run_analysis,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_progress_queues():
    """Clear progress queues around each test case."""
    _progress_queues.clear()
    yield
    _progress_queues.clear()


@pytest.mark.asyncio
async def test_emit_success():
    """Enqueue a progress event for an active session."""
    session_id = "test_session_1"
    _progress_queues[session_id] = asyncio.Queue()

    _emit(session_id, "test_stage", 50, "Test message")

    event = await _progress_queues[session_id].get()
    assert event == {"stage": "test_stage", "progress": 50, "message": "Test message"}


@pytest.mark.asyncio
async def test_emit_no_session_id():
    """Skip emitting when no session identifier is provided."""
    # Should not raise an error or add to any queue if session_id is None
    _emit(None, "test_stage", 50, "Test message")
    assert not _progress_queues  # Ensure no queue was created or modified


@pytest.mark.asyncio
async def test_emit_session_id_not_found():
    """Skip emitting when the session queue is missing."""
    # Should not raise an error if session_id is not in _progress_queues
    session_id = "non_existent_session"
    _emit(session_id, "test_stage", 50, "Test message")
    assert session_id not in _progress_queues


@pytest.mark.asyncio
async def test_emit_queue_full():
    """Drop progress updates when the session queue is full."""
    session_id = "test_session_2"
    # Create a queue with maxsize 1 and fill it
    _progress_queues[session_id] = asyncio.Queue(maxsize=1)
    await _progress_queues[session_id].put(
        {"stage": "initial", "progress": 0, "message": "Initial message"}
    )

    # Attempt to emit another message, which should cause a warning and drop the event
    with patch.object(logger, "warning") as mock_warning:
        _emit(session_id, "overflow", 100, "Overflow message")
        mock_warning.assert_called_once()
        assert (
            "Progress queue for session test_session_2 is full"
            in mock_warning.call_args[0][0]
        )

    # The queue should still only contain the first item
    assert _progress_queues[session_id].qsize() == 1
    event = await _progress_queues[session_id].get()
    assert event == {"stage": "initial", "progress": 0, "message": "Initial message"}


@patch("src.app.main.PcapParser")
@patch("src.app.main.Analyzer")
@patch("src.app.main.Report")
@patch("src.app.main._emit")
def test_run_analysis_success(
    mock_emit,
    mock_report_cls,
    mock_analyzer_cls,
    mock_pcap_parser_cls,
):
    """Run analysis successfully and persist the JSON report."""
    mock_pcap_parser_instance = mock_pcap_parser_cls.return_value
    mock_pcap_parser_instance.traffic_df = MagicMock(spec=pd.DataFrame)
    mock_pcap_parser_instance.endpoints_df = MagicMock(spec=pd.DataFrame)
    mock_pcap_parser_instance.services_df = MagicMock(spec=pd.DataFrame)

    mock_analyzer_instance = mock_analyzer_cls.return_value
    mock_report_instance = mock_report_cls.return_value
    mock_report_instance.data = {"summary": "test report"}

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_pcap:
        tmp_pcap.write(b"dummy pcap content")
        pcap_path = tmp_pcap.name

    output_path = "/tmp/test_report.json"
    session_id = "test_session_run_analysis"

    try:
        report_data = run_analysis(
            pcap_path, output_path=output_path, session_id=session_id
        )

        assert report_data == {"summary": "test report"}
        mock_pcap_parser_cls.assert_called_once()
        analyzer_args = mock_analyzer_cls.call_args.args
        assert analyzer_args[:3] == (
            mock_pcap_parser_instance.traffic_df,
            mock_pcap_parser_instance.endpoints_df,
            mock_pcap_parser_instance.services_df,
        )
        assert analyzer_args[3].__class__.__name__ == "FilePathInfo"
        mock_report_cls.assert_called_once_with(mock_analyzer_instance, report_id=ANY)

        mock_emit.assert_any_call(session_id, "zeek", 10, "Running Zeek on PCAP...")
        mock_emit.assert_any_call(
            session_id, "traffic", 35, "Processing traffic data..."
        )
        mock_emit.assert_any_call(session_id, "report", 80, "Generating report...")
        mock_emit.assert_any_call(session_id, "done", 100, "Analysis complete.")

        # Check if report was written to file
        assert Path(output_path).exists()
        with open(output_path) as f:
            content = json.load(f)
            assert content == {"summary": "test report"}

    finally:
        os.remove(pcap_path)
        if Path(output_path).exists():
            os.remove(output_path)


@patch("src.app.main.PcapParser", side_effect=Exception("PcapParser error"))
@patch("src.app.main._emit")
def test_run_analysis_pcap_parser_failure(mock_emit, mock_pcap_parser_cls):
    """Propagate parser failures after emitting initial progress."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_pcap:
        tmp_pcap.write(b"dummy pcap content")
        pcap_path = tmp_pcap.name

    session_id = "test_session_failure"

    try:
        with pytest.raises(Exception, match="PcapParser error"):
            run_analysis(pcap_path, session_id=session_id)

        mock_emit.assert_any_call(session_id, "zeek", 10, "Running Zeek on PCAP...")
        # No further emits should occur after the exception
        assert mock_emit.call_count == 1  # Only the first emit should be called
    finally:
        os.remove(pcap_path)


@pytest.mark.asyncio
async def test_analyze_endpoint_success():
    """The endpoint should:
    1. Save the uploaded file to a temporary location.
    2. Call the (synchronous) run_analysis function.
    3. Return the dict that run_analysis produces.
    """
    with patch("src.app.main.run_analysis", new_callable=Mock) as mock_run_analysis:
        mock_run_analysis.return_value = {"status": "success"}

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_pcap:
            tmp_pcap.write(b"dummy pcap content")
            tmp_pcap_path = tmp_pcap.name

        try:
            with open(tmp_pcap_path, "rb") as f:
                # response = client.request("POST", "/analyze",
                #     params={"session_id": "test_analyze_success"},
                #     files={"file": ("test.pcap", f, "application/octet-stream")}
                # )
                response = client.post(
                    "/analyze?session_id=test_analyze_success",
                    files={"file": ("test.pcap", f, "application/octet-stream")},
                )

            assert response.status_code == 200
            assert response.json() == {"status": "success"}

            # The mock must have been called exactly once.
            mock_run_analysis.assert_called_once()

            args, kwargs = mock_run_analysis.call_args

            # Positional part – only the temporary file path.
            assert len(args) == 1
            tmp_path_passed = args[0]

            # The endpoint passes a **string** that ends with ".pcap".
            # We don’t assert the file still exists because the endpoint
            # deletes it in a ``finally`` block after the response.
            assert isinstance(tmp_path_passed, str)
            assert tmp_path_passed.endswith(".pcap")

            # Keyword part – we care about the session_id.
            assert kwargs["session_id"] == "test_analyze_success"
            # The other keywords are also present; we don’t need to assert them,
            # but they exist:
            assert "output_path" in kwargs
            assert "project_root" in kwargs

        finally:
            if os.path.exists(tmp_pcap_path):
                os.remove(tmp_pcap_path)


@pytest.mark.asyncio
async def test_analyze_endpoint_invalid_file_type():
    """Reject uploads that are not PCAP files."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp_txt:
        tmp_txt.write(b"dummy text content")
        tmp_txt_path = tmp_txt.name

    with open(tmp_txt_path, "rb") as f:
        response = client.post(
            "/analyze", files={"file": ("test.txt", f, "text/plain")}
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Only .pcap files are supported"}
    os.remove(tmp_txt_path)


@pytest.mark.asyncio
async def test_analyze_endpoint_analysis_failure():
    with patch("src.app.main.run_analysis", new_callable=Mock) as mock_run_analysis:
        # Raising the exception here mimics a real failure inside the function.
        mock_run_analysis.side_effect = Exception("Internal analysis error")

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_pcap:
            tmp_pcap.write(b"dummy pcap content")
            tmp_pcap_path = tmp_pcap.name

        try:
            with open(tmp_pcap_path, "rb") as f:
                response = client.post(
                    "/analyze?session_id=test_analyze_failure",
                    files={"file": ("test.pcap", f, "application/octet-stream")},
                )

            assert response.status_code == 500
            json_body = response.json()
            assert "detail" in json_body
            assert "Analysis failed: Internal analysis error" in json_body["detail"]
            # The mock must have been called exactly once.
            mock_run_analysis.assert_called_once()

        finally:
            if os.path.exists(tmp_pcap_path):
                os.remove(tmp_pcap_path)


@pytest.mark.asyncio
async def test_websocket_progress_stream():
    """Stream queued progress updates over the WebSocket endpoint."""
    session_id = "ws_test_session"

    # Connect to the WebSocket
    with client.websocket_connect(f"/ws/progress/{session_id}") as websocket:
        # Simulate emitting some progress
        _emit(session_id, "stage1", 25, "Processing data")
        _emit(session_id, "stage2", 75, "Generating results")
        _emit(session_id, "done", 100, "Complete")

        # Receive messages
        msg1 = websocket.receive_json()
        msg2 = websocket.receive_json()
        msg3 = websocket.receive_json()

        assert msg1 == {
            "stage": "stage1",
            "progress": 25,
            "message": "Processing data",
        }
        assert msg2 == {
            "stage": "stage2",
            "progress": 75,
            "message": "Generating results",
        }
        assert msg3 == {"stage": "done", "progress": 100, "message": "Complete"}

        # After 'done', the server should close the connection.
        with pytest.raises(Exception):
            websocket.receive_json()

    # Ensure the queue is cleaned up after disconnection
    assert session_id not in _progress_queues


@pytest.mark.asyncio
async def test_websocket_disconnect_cleanup():
    """Clean up session state when the WebSocket disconnects."""
    session_id = "ws_disconnect_session"

    # Connect and immediately disconnect
    with client.websocket_connect(f"/ws/progress/{session_id}") as _:
        pass  # Connection established, then immediately closed by exiting 'with' block

    # Give a moment for the server-side cleanup to potentially run
    await asyncio.sleep(0.1)

    # Ensure the queue is cleaned up
    assert session_id not in _progress_queues


@pytest.mark.asyncio
async def test_websocket_timeout():
    """Emit an error event when the progress stream times out."""
    session_id = "ws_timeout_session"

    # Patch asyncio.wait_for to simulate a timeout quickly
    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError) as mock_wait_for:
        with client.websocket_connect(f"/ws/progress/{session_id}") as websocket:
            # The first receive should trigger the patched timeout
            msg = websocket.receive_json()
            assert msg == {
                "stage": "error",
                "progress": 0,
                "message": "Analysis timed out.",
            }
            mock_wait_for.assert_called_once()

        # Ensure the queue is cleaned up
        assert session_id not in _progress_queues
