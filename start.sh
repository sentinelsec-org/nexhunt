#!/bin/bash
# NexHunt startup script for Linux
# Handles X11 authorization automatically

cd "$(dirname "$0")"

# Detect display
if [ -z "$DISPLAY" ]; then
  export DISPLAY=:0.0
fi

# Find and export X11 auth cookie
# Try common locations for Kali/Debian
for XAUTH_FILE in \
  "/home/kali/.Xauthority" \
  "/root/.Xauthority" \
  "$HOME/.Xauthority" \
  "/var/run/lightdm/root/:0" \
  "/run/user/1000/.mutter-Xwaylandauth"*; do
  if [ -f "$XAUTH_FILE" ]; then
    export XAUTHORITY="$XAUTH_FILE"
    break
  fi
done

# Allow local X11 connections (needed when running as root)
xhost +local: >/dev/null 2>&1 || true

# Kill any leftover backend from previous session
fuser -k 17707/tcp >/dev/null 2>&1 || true
sleep 1

# Launch NexHunt
exec env -u ELECTRON_RUN_AS_NODE \
  DISPLAY="$DISPLAY" \
  XAUTHORITY="$XAUTHORITY" \
  node_modules/.bin/electron . \
  --no-sandbox \
  --disable-gpu \
  --disable-gpu-sandbox \
  --in-process-gpu \
  --disable-dev-shm-usage
