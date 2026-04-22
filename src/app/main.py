# Standard Python Libraries
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import traceback
from urllib.parse import unquote
import uuid
import warnings

# Third-Party Libraries
from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
from utils.analysis import Analyzer, FilePathInfo, PcapParser
from utils.report import Report

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Per-session progress queues - keyed by session_id, cleaned up after analysis completes
_progress_queues: dict[str, asyncio.Queue] = {}
_report_registry: dict[str, Analyzer] = {}
_executor = ThreadPoolExecutor(max_workers=4)

# Constants
PCAP_CHUNK_SIZE = 1024 * 1024  # 1MB


def _emit(session_id: str | None, stage: str, progress: int, message: str) -> None:
    """Push a progress event onto the session queue if one exists."""
    if session_id is None or session_id not in _progress_queues:
        return
    try:
        _progress_queues[session_id].put_nowait(
            {
                "stage": stage,
                "progress": progress,
                "message": message,
            }
        )
    except asyncio.QueueFull:
        logger.warning(
            f"Progress queue for session {session_id} is full. Dropping event: {message}"
        )
    except Exception as e:
        logger.error(f"Error emitting progress for session {session_id}: {e}")


def run_analysis(
    pcap_path: str,
    output_path: str | None = None,
    project_root: str | None = None,
    session_id: str | None = None,
) -> dict:
    """
    Runs the eleVADR analysis on a given PCAP file.

    Args:
        pcap_path: Path to the PCAP file.
        output_path: Optional path to save the JSON report.
        project_root: Optional project root directory.
        session_id: Optional session ID for progress reporting.

    Returns:
        The generated analysis report as a dictionary.
    """
    # Filter FutureWarnings from pandas, but keep other warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=FutureWarning)
        # pandas display options are typically for interactive use, not production code.
        # Removed pd.set_option("display.max_columns", None)

        if project_root is None:
            project_root = str(Path(__file__).resolve().parent)

        file_path_info = FilePathInfo(
            path_to_pcap=str(Path(pcap_path).resolve()),
            path_to_zeek=str(Path(project_root, "data/zeeks")),
            path_to_zeek_scripts=str(Path(project_root, "data/zeek_scripts")),
            path_to_assessor_data=str(Path(project_root, "data/assessor_data")),
        )

        _emit(session_id, "zeek", 10, "Running Zeek on PCAP...")
        pcap_parser = PcapParser(file_path_info)

        _emit(session_id, "traffic", 35, "Processing traffic data...")
        analyzer = Analyzer(
            pcap_parser.traffic_df,
            pcap_parser.endpoints_df,
            pcap_parser.services_df,
            file_path_info,
        )

        report_id = str(uuid.uuid4())
        _report_registry[report_id] = analyzer

        _emit(session_id, "report", 80, "Generating report...")
        report = Report(analyzer, report_id=report_id)

        _emit(session_id, "done", 100, "Analysis complete.")

        report_json = json.dumps(report.data, indent=4)
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(report_json)

        return report.data


app = FastAPI(
    title="eleVADR Analysis API",
    description="Upload a PCAP and run eleVADR analysis",
    version="1.0.0",
)

# Support comma-separated origins for cases where the frontend is accessed
# via multiple hostnames (e.g. localhost vs 127.0.0.1)
origins = [
    origin.strip()
    for origin in os.environ.get("FRONTEND_ORIGIN", "http://localhost:8080").split(",")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_PROJECT_ROOT = Path(
    os.environ.get("PROJECT_ROOT", Path(__file__).resolve().parent)
)


@app.websocket("/ws/progress/{session_id}")
async def progress_ws(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint that streams analysis progress events to the client.

    The client connects before POSTing to /analyze, then listens for JSON
    progress messages until the 'done' stage is received.
    """
    await websocket.accept()

    # Register a queue for this session
    queue: asyncio.Queue = asyncio.Queue(maxsize=32)
    _progress_queues[session_id] = queue
    try:
        while True:
            try:
                # Wait for a progress event with a timeout to detect dead connections
                event = await asyncio.wait_for(queue.get(), timeout=300)
                await websocket.send_json(event)
                if event.get("stage") in ["done", "error"]:
                    break
            except asyncio.TimeoutError:
                # No progress in 5 minutes - something went wrong, close the socket
                logger.warning(
                    f"WebSocket progress for session {session_id} timed out."
                )
                await websocket.send_json(
                    {"stage": "error", "progress": 0, "message": "Analysis timed out."}
                )
                break
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}.")
    except Exception as e:
        logger.error(f"Unhandled error in WebSocket for session {session_id}: {e}")
        await websocket.send_json(
            {"stage": "error", "progress": 0, "message": f"WebSocket error: {e}"}
        )
    finally:
        _progress_queues.pop(session_id, None)
        await websocket.close()


@app.get("/health")
async def health():
    return {"status": "ok"}


def _require_analyzer(report_id: str) -> Analyzer:
    analyzer = _report_registry.get(report_id)
    if analyzer is None:
        raise HTTPException(status_code=404, detail=f"Report not found: {report_id}")
    return analyzer


@app.get("/reports/{report_id}/drilldown/service/{service_name}")
async def drilldown_service(
    report_id: str,
    service_name: str,
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return detailed connection rows for a specific service name within a report."""
    try:
        decoded_service_name = unquote(service_name)
        analyzer = _require_analyzer(report_id)

        return {
            "report_id": report_id,
            "service_name": decoded_service_name,
            "connections": analyzer.service_connection_lines(
                decoded_service_name, limit=limit
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Service drilldown failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Service drilldown failed: {e}")


@app.get("/reports/{report_id}/drilldown/connection-state/{state}")
async def drilldown_connection_state(
    report_id: str,
    state: str,
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return detailed connection rows for a specific Zeek connection state within a report."""
    try:
        decoded_state = unquote(state)
        analyzer = _require_analyzer(report_id)

        return {
            "report_id": report_id,
            "state": decoded_state,
            "connections": analyzer.connections_by_state(decoded_state, limit=limit),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Connection state drilldown failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        raise HTTPException(
            status_code=500, detail=f"Connection state drilldown failed: {e}"
        )


@app.get("/reports/{report_id}/drilldown/suspicious-outbound")
async def drilldown_suspicious_outbound(
    report_id: str,
    src_ip: str = Query(...),
    dst_ip: str = Query(...),
    dst_port: int = Query(...),
    service_name: str = Query(...),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return detailed connection rows for a suspicious outbound grouping within a report."""
    try:
        analyzer = _require_analyzer(report_id)

        return {
            "report_id": report_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "service_name": service_name,
            "connections": analyzer.suspicious_outbound_connection_lines(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                service_name=service_name,
                limit=limit,
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Suspicious outbound drilldown failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        raise HTTPException(
            status_code=500, detail=f"Suspicious outbound drilldown failed: {e}"
        )


@app.get("/reports/{report_id}/drilldown/cross-segment")
async def drilldown_cross_segment(
    report_id: str,
    src_subnet: str = Query(...),
    dst_subnet: str = Query(...),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return detailed cross-segment connection rows for a source/destination subnet pair within a report."""
    try:
        analyzer = _require_analyzer(report_id)

        return {
            "report_id": report_id,
            "src_subnet": src_subnet,
            "dst_subnet": dst_subnet,
            "connections": analyzer.cross_segment_connections_by_subnet_pair(
                src_subnet=src_subnet,
                dst_subnet=dst_subnet,
                limit=limit,
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Cross-segment drilldown failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        raise HTTPException(
            status_code=500, detail=f"Cross-segment drilldown failed: {e}"
        )


@app.get("/reports/{report_id}/connections")
async def filtered_connections(
    report_id: str,
    ip: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    dst_ip: str | None = Query(default=None),
    subnet: str | None = Query(default=None),
    src_subnet: str | None = Query(default=None),
    dst_subnet: str | None = Query(default=None),
    manufacturer: str | None = Query(default=None),
    service_name: str | None = Query(default=None),
    connection_state: str | None = Query(default=None),
    direction: str | None = Query(default=None),
    success: bool | None = Query(default=None),
    is_ot: bool | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return filtered connection detail rows for a report."""
    try:
        analyzer = _require_analyzer(report_id)
        return {
            "report_id": report_id,
            "filters": {
                "ip": ip,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "subnet": subnet,
                "src_subnet": src_subnet,
                "dst_subnet": dst_subnet,
                "manufacturer": manufacturer,
                "service_name": service_name,
                "connection_state": connection_state,
                "direction": direction,
                "success": success,
                "is_ot": is_ot,
            },
            "connections": analyzer.connection_lines_filtered(
                ip=ip,
                src_ip=src_ip,
                dst_ip=dst_ip,
                subnet=subnet,
                src_subnet=src_subnet,
                dst_subnet=dst_subnet,
                manufacturer=manufacturer,
                service_name=service_name,
                connection_state=connection_state,
                direction=direction,
                success=success,
                is_ot=is_ot,
                limit=limit,
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Filtered connections drilldown failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        raise HTTPException(
            status_code=500, detail=f"Filtered connections drilldown failed: {e}"
        )


@app.get("/reports/{report_id}/devices")
async def filtered_devices(
    report_id: str,
    manufacturer: str | None = Query(default=None),
    subnet: str | None = Query(default=None),
    service_name: str | None = Query(default=None),
    is_ot: bool | None = Query(default=None),
    is_edge: bool | None = Query(default=None),
):
    """Return filtered device rows for a report."""
    try:
        analyzer = _require_analyzer(report_id)
        return {
            "report_id": report_id,
            "filters": {
                "manufacturer": manufacturer,
                "subnet": subnet,
                "service_name": service_name,
                "is_ot": is_ot,
                "is_edge": is_edge,
            },
            "devices": analyzer.devices_filtered(
                manufacturer=manufacturer,
                subnet=subnet,
                service_name=service_name,
                is_ot=is_ot,
                is_edge=is_edge,
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Filtered devices drilldown failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        raise HTTPException(
            status_code=500, detail=f"Filtered devices drilldown failed: {e}"
        )


@app.get("/reports/{report_id}/services")
async def filtered_services(
    report_id: str,
    subnet: str | None = Query(default=None),
    manufacturer: str | None = Query(default=None),
    device_ip: str | None = Query(default=None),
    risk_category: str | None = Query(default=None),
    service_name: str | None = Query(default=None),
):
    """Return filtered service rows for a report."""
    try:
        analyzer = _require_analyzer(report_id)
        return {
            "report_id": report_id,
            "filters": {
                "subnet": subnet,
                "manufacturer": manufacturer,
                "device_ip": device_ip,
                "risk_category": risk_category,
                "service_name": service_name,
            },
            "services": analyzer.services_filtered(
                subnet=subnet,
                manufacturer=manufacturer,
                device_ip=device_ip,
                risk_category=risk_category,
                service_name=service_name,
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Filtered services drilldown failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        raise HTTPException(
            status_code=500, detail=f"Filtered services drilldown failed: {e}"
        )


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    session_id: str | None = Query(default=None),
):
    """
    Upload a PCAP, run eleVADR analysis, and return the JSON report.

    Optionally accepts a session_id query param to stream progress over
    the /ws/progress/{session_id} WebSocket endpoint.
    """
    filename = file.filename or ""
    if not filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are supported")

    tmp_path: str | None = None

    try:
        # Save to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            while True:
                chunk = await file.read(PCAP_CHUNK_SIZE)
                if not chunk:
                    break
                tmp.write(chunk)
            tmp_path = tmp.name

        _emit(session_id, "upload", 5, "PCAP uploaded, starting analysis...")

        # Run the blocking analysis in a thread so the event loop stays free
        # to service the WebSocket progress stream concurrently
        loop = asyncio.get_event_loop()
        report_data = await loop.run_in_executor(
            _executor,
            lambda: run_analysis(
                tmp_path,
                output_path=None,
                project_root=str(DEFAULT_PROJECT_ROOT),
                session_id=session_id,
            ),
        )

        return report_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Analysis failed: %s", e)
        logger.error("Traceback:\n%s", traceback.format_exc())
        _emit(session_id, "error", 0, f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError as e:
                logger.error(f"Error removing temporary file {tmp_path}: {e}")


# CLI entrypoint stays as-is
if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(
        description="eleVADR - OT Network Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    argument_parser.add_argument(
        "--pcap",
        type=str,
        required=True,
        default=os.environ.get("PCAP_INPUT"),
        help="Path to PCAP file (can also use PCAP_INPUT env var)",
    )

    argument_parser.add_argument(
        "--output",
        type=str,
        default=os.environ.get("REPORT_OUTPUT"),
        help="Output path for JSON report (can also use REPORT_OUTPUT env var, default: stdout)",
    )

    argument_parser.add_argument(
        "--project-root",
        type=str,
        default=os.getcwd(),
        help="Project root directory (default: parent of main.py)",
    )

    args = argument_parser.parse_args()

    if not Path(args.pcap).exists():
        logger.error(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)

    try:
        run_analysis(args.pcap, args.output, args.project_root)
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        logger.error("Traceback:\n%s", traceback.format_exc())
        sys.exit(1)
