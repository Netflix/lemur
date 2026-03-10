#!/bin/bash
set -e

# Run db upgrade before main command.
# Requires: SQLALCHEMY_DATABASE_URI; uses LEMUR_CONF or lemur/tests/conf.py
if [ -n "${SQLALCHEMY_DATABASE_URI}" ]; then
  echo "--> Running database migrations"
  export LEMUR_CONF="${LEMUR_CONF:-/app/lemur/tests/conf.py}"
  cd /app/lemur && lemur db upgrade || echo "--> db upgrade skipped or failed"
  cd /app
  echo "--> Done"
fi

exec "$@"
