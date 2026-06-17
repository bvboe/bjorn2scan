#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "Updater Integration Test"
echo "========================================="
echo ""

# Build Docker image
echo -e "${YELLOW}Building test Docker image...${NC}"
cd "$(dirname "$0")/../../.."
docker build -t bjorn2scan-updater-test -f bjorn2scan-agent/updater/integration_test/Dockerfile .

echo ""
echo -e "${YELLOW}Starting test container...${NC}"

# Run tests in Docker
docker run --rm \
  -v "$(pwd)/bjorn2scan-agent/updater/integration_test:/test" \
  bjorn2scan-updater-test \
  /test/test-scenarios.sh

echo ""
echo -e "${GREEN}All tests completed!${NC}"
