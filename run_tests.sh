#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  run_tests.sh — SecureJobs
#  Install test dependencies and run the full test suite.
#
#  Usage (from project root):
#    chmod +x run_tests.sh
#    bash run_tests.sh
# ─────────────────────────────────────────────────────────────

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== SecureJobs Test Suite ===${NC}"
echo ""

# ── Install test dependencies ─────────────────────────────────
echo -e "${YELLOW}Installing test dependencies...${NC}"
pip install pytest pytest-asyncio httpx --quiet

# ── Run tests ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Running all tests...${NC}"
echo ""

pytest tests/ -v \
    --tb=short \
    -p no:warnings

# ── Cleanup test DB file ──────────────────────────────────────
rm -f test_securejobs.db
echo ""
echo -e "${GREEN}Test run complete. Temporary DB removed.${NC}"
