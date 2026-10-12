#!/usr/bin/env bash
# scripts/ci_container_smoke.sh
# Container Build & Health Parity Smoke Test Script
# Can be run in local Linux/Docker environment or CI.

set -euo pipefail

COMMIT_SHA=$(git rev-parse HEAD)
echo "Building Basebreak container image for commit: ${COMMIT_SHA}"

docker build \
  --build-arg BUILD_COMMIT_SHA="${COMMIT_SHA}" \
  -t basebreak:ci-test .

echo "Starting container on port 8080..."
CONTAINER_ID=$(docker run -d --rm -p 8080:8080 basebreak:ci-test)

# Allow container startup
sleep 4

echo "Probing /health endpoint..."
HEALTH_JSON=$(curl -fsS http://127.0.0.1:8080/health || (docker logs "${CONTAINER_ID}" && exit 1))
echo "Health response: ${HEALTH_JSON}"

REPORTED_SHA=$(python3 -c "import json; print(json.loads('''${HEALTH_JSON}''')['commit_sha'])")

if [ "${REPORTED_SHA}" != "${COMMIT_SHA}" ]; then
  echo "Commit SHA mismatch! Expected: ${COMMIT_SHA}, Got: ${REPORTED_SHA}"
  docker logs "${CONTAINER_ID}"
  docker stop "${CONTAINER_ID}"
  exit 1
fi

echo "Container build and source SHA parity smoke test PASSED."
docker stop "${CONTAINER_ID}"
