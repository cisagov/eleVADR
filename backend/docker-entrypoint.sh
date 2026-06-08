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

if [ "$ELEVADR_MODE" = "api" ]; then
  echo -e "${YELLOW}Starting eleVADR in API mode (FastAPI/uvicorn) on port ${API_PORT}...${NC}"

  if ! command -v zeek &> /dev/null; then
    echo -e "${RED}Error: Zeek is not installed or not in PATH${NC}"
    exit 1
  fi

  cd /app
  exec /app/.venv/bin/python -m uvicorn src.app.main:app --host 0.0.0.0 --port "${API_PORT}" --log-level info
fi
