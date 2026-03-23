#!/usr/bin/env bash
#
# Run PdoCache functional tests against all supported database engines.
# Everything runs inside Docker — no local PHP or database extensions needed.
#
# Usage:
#   ./bin/test-databases.sh          # Build, test, tear down
#   ./bin/test-databases.sh --keep   # Keep containers running after tests
#
# Requirements: docker compose

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.test.yml"
COMPOSE="docker compose -f ${COMPOSE_FILE}"
KEEP_CONTAINERS=false

if [[ "${1:-}" == "--keep" ]]; then
    KEEP_CONTAINERS=true
fi

cleanup() {
    if [[ "$KEEP_CONTAINERS" == false ]]; then
        echo ""
        echo "Stopping test containers..."
        $COMPOSE down --volumes --remove-orphans 2>/dev/null || true
    fi
}

trap cleanup EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASSED=0
FAILED=0

run_test() {
    local label="$1"
    local dsn="$2"
    local user="${3:-}"
    local password="${4:-}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ${label}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if $COMPOSE run --rm \
        -e "PHIREWALL_PDO_DSN=${dsn}" \
        -e "PHIREWALL_PDO_USER=${user}" \
        -e "PHIREWALL_PDO_PASSWORD=${password}" \
        -e "XDEBUG_MODE=off" \
        php vendor/bin/phpunit --no-coverage --group=database --colors=always; then
        echo -e "  ${GREEN}✓ ${label} passed${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}✗ ${label} failed${NC}"
        FAILED=$((FAILED + 1))
    fi
}

echo "╔══════════════════════════════════════════════════╗"
echo "║  Phirewall PdoCache Database Test Suite          ║"
echo "╚══════════════════════════════════════════════════╝"

# Build PHP image and start database containers
echo ""
echo "Building PHP image and starting databases..."
$COMPOSE build php
$COMPOSE up -d mysql postgres
$COMPOSE run --rm php composer install --prefer-dist --no-progress --no-interaction --quiet

# Wait for services to be healthy
echo "Waiting for databases to be ready..."
$COMPOSE up -d --wait mysql postgres

# SQLite
run_test "SQLite (in-memory)" "sqlite::memory:"

# MySQL (service name resolves via Docker network)
run_test "MySQL 8" \
    "mysql:host=mysql;port=3306;dbname=phirewall_test" \
    "root" \
    "phirewall_test"

# PostgreSQL
run_test "PostgreSQL 16" \
    "pgsql:host=postgres;port=5432;dbname=phirewall_test" \
    "phirewall_test" \
    "phirewall_test"

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ "$KEEP_CONTAINERS" == true ]]; then
    echo ""
    echo "Containers still running. Stop with:"
    echo "  docker compose -f docker-compose.test.yml down --volumes"
fi

exit "$FAILED"
