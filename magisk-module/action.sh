#!/system/bin/sh
# Root manager "Action" button (Magisk and KernelSU): restore immediately with
# the pure-shell hook, then hand the phone roles back to the system phone app
# when DialCrypt holds them.
# Prints the exit code of the hook (0 restored, 75 something still pending) and,
# only when DialCrypt held a phone role, one line: dialer=<package> or dialer=failed.
HOOK=/data/adb/service.d/aegis-restore.sh
[ -f "$HOOK" ] || HOOK=${0%/*}/aegis-restore.sh
/system/bin/sh "$HOOK" --now
echo "rc=$?"

APP_PKG=io.github.h4lovoid.dialcrypt
FALLBACK_DIALER=com.google.android.dialer

# The phone app built into the system image (first line of the command output).
system_dialer=$(cmd telecom get-system-dialer 2>/dev/null | head -n 1 | tr -d '[:space:]')
case "$system_dialer" in
  *[!A-Za-z0-9._]*) system_dialer= ;;
esac
case "$system_dialer" in
  [A-Za-z]*.*) ;;
  *) system_dialer=$FALLBACK_DIALER ;;
esac
[ "$system_dialer" = "$APP_PKG" ] && system_dialer=$FALLBACK_DIALER

# Success when the holder list of role $1 names DialCrypt as a whole word.
held_by_app() {
  holders=$(cmd role get-role-holders --user 0 "$1" 2>/dev/null)
  case " $holders " in
    *[!A-Za-z0-9._]"$APP_PKG"[!A-Za-z0-9._]*) return 0 ;;
  esac
  return 1
}

handed_back=0
hand_back_failed=0
for role in android.app.role.DIALER android.app.role.CALL_SCREENING; do
  held_by_app "$role" || continue
  if cmd role add-role-holder --user 0 "$role" "$system_dialer" >/dev/null 2>&1; then
    handed_back=1
  else
    hand_back_failed=1
  fi
done
if [ "$hand_back_failed" = 1 ]; then
  echo "dialer=failed"
elif [ "$handed_back" = 1 ]; then
  echo "dialer=$system_dialer"
fi
