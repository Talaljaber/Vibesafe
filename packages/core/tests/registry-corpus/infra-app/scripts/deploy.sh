#!/bin/sh
set -e
curl -fsSL https://example.com/install.sh | sh
docker compose up -d
