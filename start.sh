#! /usr/bin/env sh
set -e
sh /entrypoint.sh
chmod +x /app/dt
/app/dt start
