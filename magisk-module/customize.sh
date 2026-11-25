# Module installer hook (sourced by the Magisk or KernelSU installer, not executed;
# both provide MODPATH and set_perm).
# Installs the boot restore hook into /data/adb/service.d so that a journal is
# restored on every boot even if this module is later disabled or removed,
# creates a default policy (dry run: armed=0, dedicated_mode=0) and pins the
# signing certificate of the bundled app in it.
mkdir -p /data/adb/aegischat /data/adb/service.d
chmod 0700 /data/adb/aegischat
if [ ! -f /data/adb/aegischat/policy.conf ]; then
  printf '%s\n' 'armed=0' 'dedicated_mode=0' > /data/adb/aegischat/policy.conf
fi
chmod 0600 /data/adb/aegischat/policy.conf
# tools/android-build/build.sh writes the SHA-256 of the app's signing certificate
# to app_cert_sha256 at the module root. Set it as app_cert_sha256 in the policy,
# replacing an earlier value: the app this module installs is the one the daemon
# has to accept, so a new signing key needs no edit by hand.
AEGIS_POLICY=/data/adb/aegischat/policy.conf
aegis_cert=
if [ -f "$MODPATH/app_cert_sha256" ]; then
  aegis_cert=$(tr -d '[:space:]' < "$MODPATH/app_cert_sha256")
fi
case "$aegis_cert" in
  *[!0-9a-f]*) aegis_cert= ;;
esac
if [ ${#aegis_cert} -eq 64 ]; then
  grep -v '^[[:space:]]*app_cert_sha256[[:space:]]*=' "$AEGIS_POLICY" > "$AEGIS_POLICY.new"
  printf 'app_cert_sha256=%s\n' "$aegis_cert" >> "$AEGIS_POLICY.new"
  chmod 0600 "$AEGIS_POLICY.new"
  mv -f "$AEGIS_POLICY.new" "$AEGIS_POLICY"
  ui_print "- App signing certificate pinned in $AEGIS_POLICY"
else
  ui_print "- No app certificate in this module: set app_cert_sha256 in $AEGIS_POLICY by hand"
fi
cp -f "$MODPATH/aegis-restore.sh" /data/adb/service.d/aegis-restore.sh
chmod 0755 /data/adb/service.d/aegis-restore.sh
# The installer may leave module files with umask-dependent modes. Set the
# priv-app, its permission allowlist and the other system files root:root
# 0755/0644 with the system_file label, then make the daemon executable.
if [ -d "$MODPATH/system" ]; then
  set_perm_recursive "$MODPATH/system" 0 0 0755 0644
fi
if [ -f "$MODPATH/system/bin/aegiscalld" ]; then
  set_perm "$MODPATH/system/bin/aegiscalld" 0 0 0755
fi
