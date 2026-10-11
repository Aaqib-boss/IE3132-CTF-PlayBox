#!/usr/bin/env bash
# Reset Stage 3 (stateless Flask app) to a fresh container.
set -euo pipefail
cd "$(dirname "$0")/../stages/stage3_web"
docker compose -f docker-compose.stage3.yml up -d --force-recreate
