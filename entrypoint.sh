#!/usr/bin/env bash
set -e
python3 /app/apps/manage.py makemigrations common users perms navis likes
python3 /app/apps/manage.py makemigrations
python3 /app/apps/manage.py migrate
python3 /app/apps/manage.py loaddata /app/apps/fixtures/init.json
python3 /app/apps/manage.py collectstatic --no-input
