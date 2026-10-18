#!/bin/bash
# Fixture deploy script. References a secret-bearing variable on purpose.
set -euo pipefail
echo "deploying with token $DEPLOY_TOKEN"
gunicorn app:app
