#!/bin/bash
# NexHunt startup script for Linux
# Handles X11 authorization automatically

NEXHUNT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$NEXHUNT_DIR"

find_electron() {
  local local_binary system_binary
  local_binary="$(env -u ELECTRON_RUN_AS_NODE node -e "try { const fs=require('fs'); const p=require('electron'); if (p && fs.existsSync(p)) process.stdout.write(p) } catch (_) {}" 2>/dev/null)"
  if [ -n "$local_binary" ] && [ -x "$local_binary" ]; then
    printf '%s\n' "$NEXHUNT_DIR/node_modules/.bin/electron"
    return 0
  fi
  system_binary="$({
      command -v electron 2>/dev/null || true
      for candidate in /usr/bin/electron[0-9]*; do
        [ -x "$candidate" ] && printf '%s\n' "$candidate"
      done
    } | sort -V | tail -n 1)"
  if [ -n "$system_binary" ] && [ -x "$system_binary" ]; then
    printf '%s\n' "$system_binary"
    return 0
  fi
  return 1
}

ELECTRON_BIN="$(find_electron || true)"
if [ -z "$ELECTRON_BIN" ]; then
  echo "NexHunt: Electron runtime is missing. Attempting repair..." >&2
  if [ "$(id -u)" -eq 0 ] && command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm electron || true
  elif command -v npm >/dev/null 2>&1 && { [ "$(id -u)" -eq 0 ] || [ -w "$NEXHUNT_DIR" ]; }; then
    unset NODE_ENV NPM_CONFIG_PRODUCTION npm_config_production NPM_CONFIG_OMIT npm_config_omit
    npm install --omit=dev --no-audit --no-fund || true
  fi
  ELECTRON_BIN="$(find_electron || true)"
fi

if [ -z "$ELECTRON_BIN" ] || [ ! -x "$ELECTRON_BIN" ]; then
  echo "NexHunt could not find a working Electron runtime." >&2
  echo "Repair the installation with:" >&2
  if command -v pacman >/dev/null 2>&1; then
    echo "  sudo pacman -S electron" >&2
  else
    echo "  cd $NEXHUNT_DIR && sudo env -u NODE_ENV npm install --omit=dev --no-audit --no-fund" >&2
  fi
  exit 1
fi

# The installer needs root, the desktop app does not. If somebody starts it
# with sudo, repair dependencies first and then return to the desktop user so
# Electron, Wayland/X11 and ~/.nexhunt use the correct session and ownership.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  USER_ID="$(id -u "$SUDO_USER")"
  exec sudo -u "$SUDO_USER" env \
    HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)" \
    DISPLAY="${DISPLAY:-}" \
    WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$USER_ID}" \
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$USER_ID/bus}" \
    bash "$NEXHUNT_DIR/start.sh" "$@"
fi

# Detect display
if [ -z "$DISPLAY" ]; then
  export DISPLAY=:0.0
fi

# Find and export X11 auth cookie
# Try common locations for Kali/Debian
for XAUTH_FILE in \
  "/home/kali/.Xauthority" \
  "${HOME}/.Xauthority" \
  "/root/.Xauthority" \
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
  "$ELECTRON_BIN" . \
  --no-sandbox \
  --ozone-platform-hint=auto \
  --disable-gpu \
  --disable-gpu-sandbox \
  --in-process-gpu \
  --disable-dev-shm-usage
