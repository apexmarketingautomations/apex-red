#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="$ROOT/docker/docker-compose.yml"

echo ""
echo "  ██████╗ ███████╗██████╗     ██████╗ ███████╗██████╗ "
echo "  ██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔══██╗"
echo "  ██████╔╝█████╗  ██║  ██║    ██████╔╝█████╗  ██║  ██║"
echo "  ██╔══██╗██╔══╝  ██║  ██║    ██╔══██╗██╔══╝  ██║  ██║"
echo "  ██║  ██║███████╗██████╔╝    ██║  ██║███████╗██████╔╝"
echo "  ╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝╚═════╝ "
echo ""
echo "  Autonomous Red Team Platform"
echo ""

# Check for .env
if [ ! -f "$ROOT/.env" ]; then
  if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "  ✗  ANTHROPIC_API_KEY not set."
    echo "     Copy .env.example to .env and fill it in, or:"
    echo "     export ANTHROPIC_API_KEY=sk-ant-..."
    echo ""
    exit 1
  fi
  export ANTHROPIC_API_KEY
else
  export $(grep -v '^#' "$ROOT/.env" | xargs)
fi

# Check Docker
if ! docker info &>/dev/null; then
  echo "  ✗  Docker is not running. Start Docker Desktop and try again."
  exit 1
fi

echo "  Starting infrastructure..."
docker compose -f "$COMPOSE" up -d postgres temporal reconftw nuclei

echo "  Waiting for Postgres..."
until docker exec apex-red-postgres pg_isready -U apexred &>/dev/null; do sleep 1; done

echo "  Waiting for Temporal..."
until docker exec apex-red-temporal temporal operator cluster health --address localhost:7233 &>/dev/null; do sleep 2; done

echo "  Starting API + UI..."
docker compose -f "$COMPOSE" up -d api ui

echo ""
echo "  ✓  Apex Red is running"
echo ""
echo "  Dashboard  →  http://localhost:3000"
echo "  API        →  http://localhost:4000"
echo "  Temporal   →  http://localhost:8233"
echo ""
echo "  Quick scan:"
echo "  node cli/src/index.ts start -t yourdomain.com"
echo ""
