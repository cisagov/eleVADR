#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Mode selection: "cli" (default) or "api"
ELEVADR_MODE="${ELEVADR_MODE:-cli}"
API_PORT="${API_PORT:-8000}"

echo -e "${GREEN}eleVADR - OT Network Security Analysis${NC}"
echo "=========================================="
echo -e "${YELLOW}Startup mode:${NC} ${ELEVADR_MODE}"

# --------------------------------------------------------------------
# API MODE: start FastAPI/uvicorn server, no fixed PCAP at startup
# --------------------------------------------------------------------
if [ "$ELEVADR_MODE" = "api" ]; then
  echo -e "${YELLOW}Starting eleVADR in API mode (FastAPI/uvicorn) on port ${API_PORT}...${NC}"

  if ! command -v zeek &> /dev/null; then
    echo -e "${RED}Error: Zeek is not installed or not in PATH${NC}"
    exit 1
  fi

  cd /app
  exec uv run uvicorn app.main:app --host 0.0.0.0 --port "${API_PORT}" --log-level info
fi

# --------------------------------------------------------------------
# CLI MODE: run analysis once on PCAP_INPUT
# --------------------------------------------------------------------

# Default paths - can be overridden by environment variables
PCAP_INPUT=${PCAP_INPUT:-/input/capture.pcap}
REPORT_OUTPUT=${REPORT_OUTPUT:-/output/report.json}

# Check if input PCAP exists
if [ ! -f "$PCAP_INPUT" ]; then
  echo -e "${RED}Error: PCAP file not found at $PCAP_INPUT${NC}"
  echo "Please mount your PCAP file to /input/capture.pcap or set PCAP_INPUT environment variable"
  exit 1
fi

# Verify Zeek installation
if ! command -v zeek &> /dev/null; then
  echo -e "${RED}Error: Zeek is not installed or not in PATH${NC}"
  exit 1
fi

echo -e "${GREEN}Found PCAP:${NC} $PCAP_INPUT"
PCAP_SIZE=$(du -h "$PCAP_INPUT" | cut -f1)
echo -e "${GREEN}PCAP Size:${NC} $PCAP_SIZE"

# Get PCAP filename for processing
PCAP_FILENAME=$(basename "$PCAP_INPUT")

# Copy PCAP to uploads directory so the app can access it
echo -e "${YELLOW}Preparing PCAP for analysis...${NC}"
mkdir -p /app/data/uploads
cp "$PCAP_INPUT" /app/data/uploads/

# Run the analysis using main.py
echo -e "${YELLOW}Starting analysis...${NC}"
cd /app

uv run python main.py \
  --pcap "data/uploads/${PCAP_FILENAME}" \
  --output "$REPORT_OUTPUT" 2>&1 | while IFS= read -r line; do
  echo -e "${YELLOW}${line}${NC}"
done

# Check if report was generated successfully
if [ -f "$REPORT_OUTPUT" ]; then
  REPORT_SIZE=$(du -h "$REPORT_OUTPUT" | cut -f1)
  echo -e "${GREEN}Analysis complete!${NC}"
  echo -e "${GREEN}Report saved to:${NC} $REPORT_OUTPUT ($REPORT_SIZE)"

  # Extract and display summary if jq is available
  echo ""
  echo "Summary:"
  echo "--------"
  if command -v jq &> /dev/null; then
    jq -r '.modules.device_panel | "Total Hosts: \(.hosts)\nOT Hosts: \(.ot_hosts)\nCross-Segment OT: \(.ot_cross_segment)"' "$REPORT_OUTPUT" 2> /dev/null || echo "Report generated successfully"
  else
    echo "Report generated successfully. Install jq to view inline summary."
  fi
else
  echo -e "${RED}Error: Report generation failed${NC}"
  exit 1
fi

# Cleanup temporary PCAP copy
rm -f /app/data/uploads/"${PCAP_FILENAME}"

echo ""
echo -e "${GREEN}Container execution complete${NC}"
