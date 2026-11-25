#!/system/bin/sh
# DialCrypt Systemless Module — Bootloop Guard (2-Strike Auto-Disable)
# Only uses the module "disable" marker and /data/adb, which Magisk and KernelSU share.
MODDIR="${0%/*}"
GUARD_FILE="/data/adb/aegischat_boot_count"

# Increment boot counter on early boot; service.sh resets it once sys.boot_completed=1
COUNT=0
if [ -f "$GUARD_FILE" ]; then
    COUNT="$(cat "$GUARD_FILE" 2>/dev/null || echo 0)"
fi
COUNT=$((COUNT + 1))
echo "$COUNT" > "$GUARD_FILE"

if [ "$COUNT" -ge 2 ]; then
    # Previous boot failed to reach sys.boot_completed=1 -> disable module automatically
    touch "$MODDIR/disable"
    echo "0" > "$GUARD_FILE"
    log -t AegisChatGuard "Bootloop guard tripped (count=$COUNT); module auto-disabled safely."
    exit 0
fi

# Never mutate read-only /vendor partition directly; runtime audio hooks stay userspace-managed.
log -t AegisChatGuard "post-fs-data initialized safely (boot attempt=$COUNT)."

# KernelSU without a metamodule does not mount module files over /system (Magisk and
# metamodules do). Mount the priv-app and its permission allowlist here so the package
# manager finds them at boot. The upper layer lives in /dev and is gone after a reboot;
# the real /system is never written. Another module may overlay the same directory:
# each overlay uses whatever is mounted there as its lower layer, so both stay visible.
aegis_overlay() {
    # $1 = name, $2 = directory inside the module, $3 = system directory
    [ -d "$2" ] || return 0
    AEGIS_OV="/dev/aegis_ov/$1"
    mkdir -p "$AEGIS_OV/u" "$AEGIS_OV/w" "$AEGIS_OV/m" || return 0
    cp -a "$2/." "$AEGIS_OV/u/" || return 0
    chcon -R u:object_r:system_file:s0 "$AEGIS_OV/u" 2>/dev/null
    mount -t overlay overlay -o "lowerdir=$3,upperdir=$AEGIS_OV/u,workdir=$AEGIS_OV/w" "$AEGIS_OV/m" 2>/dev/null || return 0
    mount --bind "$AEGIS_OV/m" "$3" 2>/dev/null || log -t AegisChatGuard "overlay bind failed for $1"
}
if { [ "${KSU:-}" = "true" ] || [ -e /data/adb/ksud ]; } && [ ! -e /data/adb/metamodule ]; then
    aegis_overlay app "$MODDIR/system/priv-app" /system/priv-app
    aegis_overlay perm "$MODDIR/system/etc/permissions" /system/etc/permissions
    aegis_overlay sysconfig "$MODDIR/system/etc/sysconfig" /system/etc/sysconfig
fi
