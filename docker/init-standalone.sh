#!/usr/bin/env bash

set -e

APP_PATH="${FASTAPI_CONFIG_PATH:-/src/app.conf}"

if [ ! -e "$APP_PATH" ]; then
  echo "--------------------------------------------"
  echo " APP.CONF IS NOT MOUNTED"
  echo "--------------------------------------------"
  echo ""
  echo "In order to run this module standalone, an app.conf"
  echo "is needed. Please mount an existing app.conf into the"
  echo "container in order to run."
  echo ""
  echo "    docker run --mount type=bind,source=./app.conf,target=$APP_PATH ..."
  echo ""
  exit 1
fi

echo "--------------------------------------------"
echo "Starting main application"
echo "--------------------------------------------"

python -m app.main
