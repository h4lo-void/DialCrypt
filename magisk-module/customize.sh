# Module installer hook (sourced by the Magisk or KernelSU installer, not executed;
# both provide MODPATH and set_perm).
# Installs the boot restore hook into /data/adb/service.d so that a journal is
# restored on every boot even if this module is later disabled or removed,
# and creates a default policy (dry run: armed=0, dedicated_mode=0).
mkdir -p /data/adb/aegischat /data/adb/service.d
chmod 0700 /data/adb/aegischat
if [ ! -f /data/adb/aegischat/policy.conf ]; then
  printf '%s\n' 'armed=0' 'dedicated_mode=0' > /data/adb/aegischat/policy.conf
fi
chmod 0600 /data/adb/aegischat/policy.conf
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
