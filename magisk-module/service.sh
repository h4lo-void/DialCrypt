#!/system/bin/sh
# DialCrypt service: refresh the boot restore hook, recover a journal left by
# a crash or reboot, then keep aegiscalld running (restart within 1 second).
# Runs the same under Magisk and KernelSU (root manager neutral); aegiscalld
# inherits this script's SELinux domain (magisk or ksu, see sepolicy.rule).
MODDIR=${0%/*}
GUARD_FILE=/data/adb/aegischat_boot_count
DAEMON=$MODDIR/system/bin/aegiscalld

n=0
while [ "$(getprop sys.boot_completed)" != 1 ] && [ $n -lt 150 ]; do
  sleep 2
  n=$((n + 1))
done
[ "$(getprop sys.boot_completed)" = 1 ] && echo 0 > "$GUARD_FILE"

# The hook in service.d also runs when this module is disabled or removed.
if [ -f "$MODDIR/aegis-restore.sh" ]; then
  mkdir -p /data/adb/service.d
  cp -f "$MODDIR/aegis-restore.sh" /data/adb/service.d/aegis-restore.sh
  chmod 0755 /data/adb/service.d/aegis-restore.sh
fi

# Only Google Pixel devices are supported.
[ "$(getprop ro.product.manufacturer)" = Google ] || exit 0
# Some installers reset module file modes after customize.sh; restore the exec bit.
[ -f "$DAEMON" ] && [ ! -x "$DAEMON" ] && chmod 0755 "$DAEMON"
if [ ! -x "$DAEMON" ]; then
  # The module was packaged without the daemon binary (see BUILD.md).
  log -p e -t aegischat "E_DAEMON_MISSING $DAEMON not found or not executable; secure sessions unavailable" 2>/dev/null
  exit 0
fi

"$DAEMON" --recover-boot >/dev/null 2>&1

APP_PKG=io.github.h4lovoid.dialcrypt
# Runtime permissions of the call link (CallPermissions.RUNTIME). The app never asks for them
# itself, so a fresh install or cleared app data would leave secure calls without them. A
# permission the owner switched off in Settings (USER_SET / USER_FIXED) is left off.
# WRITE_CALL_LOG lets the app remove the call log entry of a call it handled.
# POST_NOTIFICATIONS lets the app post its call notifications when it is the default phone app.
# This script never assigns a role (see BUILD.md).
perm_state=$(dumpsys package "$APP_PKG" 2>/dev/null)
for perm in CALL_PHONE READ_PHONE_STATE ANSWER_PHONE_CALLS READ_CALL_LOG WRITE_CALL_LOG RECORD_AUDIO POST_NOTIFICATIONS; do
  line=$(printf '%s\n' "$perm_state" | grep -m1 "android.permission.$perm: granted=")
  case "$line" in
    *granted=true*) continue ;;
    *USER_SET*|*USER_FIXED*|*POLICY_FIXED*) continue ;;
  esac
  pm grant "$APP_PKG" "android.permission.$perm" >/dev/null 2>&1
done
# Compile the app ahead of time (skipped when already done). Android 16's JIT crashed the app
# while compiling one of its loops (SIGSEGV in HInductionVarAnalysis::VisitLoop, ART module
# 373041800); methods compiled ahead of time are not JIT-compiled.
(cmd package compile -m speed "$APP_PKG" >/dev/null 2>&1 &)

while true; do
  "$DAEMON" >/dev/null 2>&1 &
  pid=$!
  echo -1000 > "/proc/$pid/oom_score_adj" 2>/dev/null
  wait "$pid"
  rc=$?
  # 77 not root, 78 unsupported device: back off instead of spinning.
  if [ "$rc" -eq 77 ] || [ "$rc" -eq 78 ]; then
    sleep 30
  else
    sleep 1
  fi
done
