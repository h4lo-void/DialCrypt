#!/system/bin/sh
# DialCrypt restore hook, installed as /data/adb/service.d/aegis-restore.sh.
#
# Pure POSIX sh: it needs neither aegiscalld, nor this module being enabled,
# nor the Magisk app. It reads /data/adb/aegischat/journal.v1 and undoes every
# recorded change in the order of the design (6.7), then removes the firewall
# chains. Journal fields are validated against fixed patterns and are only
# ever passed as quoted arguments to fixed commands; nothing read from the
# journal is evaluated, sourced or used as a command name.
#
#   aegis-restore.sh                        boot: wait for boot, then restore
#   aegis-restore.sh --now                  restore immediately (action.sh)
#   aegis-restore.sh --print-plan FILE BOOT print the steps, change nothing
#   aegis-restore.sh --test-restore FILE BOOT
#       test harness: full flow (lock FILE.lock, plan, delete FILE) on FILE
#       only; prints the steps and runs no system command
#
# Locking: /data/adb/aegischat/restore.lock is shared with aegiscalld, which
# holds it from the first journal write of a session until that session's
# journal is restored and removed. This script therefore only ever reads and
# deletes a journal that no live daemon session owns. The owner file holds
# "<pid> <boot_id> <starttime>"; a lock from another boot, or whose process
# is gone or has a different start time, is stale.
#
# The parser and the plan must stay identical to daemon/src/journal.rs and
# daemon/src/commands.rs; the daemon test suite compares both outputs.

LC_ALL=C
export LC_ALL
set -f

JOURNAL=/data/adb/aegischat/journal.v1
LOCKDIR=/data/adb/aegischat/restore.lock
TAB=$(printf '\t')
NL='
'
MODE=boot
CUR_BOOT=
TESTRUN=0
LOCK_WAIT=180
case "$1" in
  --now) MODE=now ;;
  --print-plan) MODE=plan; JOURNAL=$2; CUR_BOOT=$3 ;;
  --test-restore) MODE=plan; TESTRUN=1; JOURNAL=$2; CUR_BOOT=$3; LOCKDIR=$2.lock; LOCK_WAIT=3 ;;
  '') ;;
  *) exit 64 ;;
esac
if [ "$MODE" != plan ]; then
  PATH=/system/bin:/system/xbin
  export PATH
fi

FAILED=0
HDR_OK=0
HDR_BOOT=
SAME_BOOT=0
B0= ; B1= ; B2= ; B3= ; B4= ; B5= ; B6=

is_token() {
  case "$1" in ''|*[!A-Za-z0-9._:/,=-]*) return 1 ;; esac
  [ ${#1} -le 255 ]
}

is_digits() { # value max_len
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ ${#1} -le "$2" ]
}

is_pkg() {
  case "$1" in ''|*[!A-Za-z0-9._]*|*..*|*.|[!A-Za-z]*) return 1 ;; esac
  case "$1" in *.*) ;; *) return 1 ;; esac
  [ ${#1} -le 255 ]
}

is_key() {
  case "$1" in ''|*[!A-Za-z0-9_]*) return 1 ;; esac
  [ ${#1} -le 128 ]
}

# CRC-32/IEEE of $1 as 8 lowercase hex digits. Works with 32-bit (mksh) and
# 64-bit shell arithmetic: every value is masked back to 32 bits.
crc_hex() {
  cc=$(( 0x7FFFFFFF * 2 + 1 ))
  cp=$(( 0x76DC4190 * 2 ))
  for cb in $(printf '%s' "$1" | od -An -v -tu1); do
    cc=$(( cc ^ cb ))
    ck=0
    while [ $ck -lt 8 ]; do
      cc=$(( ((cc >> 1) & 0x7FFFFFFF) ^ (cp & -(cc & 1)) ))
      ck=$((ck + 1))
    done
  done
  cc=$(( cc ^ (0x7FFFFFFF * 2 + 1) ))
  ch=
  ck=28
  while [ $ck -ge 0 ]; do
    cd=$(( (cc >> ck) & 15 ))
    case $cd in 10) cd=a ;; 11) cd=b ;; 12) cd=c ;; 13) cd=d ;; 14) cd=e ;; 15) cd=f ;; esac
    ch="$ch$cd"
    ck=$((ck - 4))
  done
  printf '%s' "$ch"
}

parse_header() {
  hl=$1
  case "$hl" in *"$TAB$TAB"*|"$TAB"*|*"$TAB") return 1 ;; esac
  IFS=$TAB read -r h1 h2 h3 h4 hx <<EOF
$hl
EOF
  [ "$h1" = ACTIVE ] && [ -z "$hx" ] || return 1
  is_token "$h2" || return 1
  case "$h3" in *[!0-9a-f]*) return 1 ;; esac
  [ ${#h3} -eq 16 ] || return 1
  hp=${h4%%:*}
  hs=${h4#*:}
  [ "$hp:$hs" = "$h4" ] || return 1
  is_digits "$hp" 9 && is_digits "$hs" 19 || return 1
  HDR_BOOT=$h2
  return 0
}

# Sets E_KIND E_TARGET E_PRIOR for a valid INTENT line.
parse_entry() {
  el=$1
  [ $(( ${#el} + 1 )) -le 1024 ] || return 1
  case "$el" in *"$TAB$TAB"*|"$TAB"*|*"$TAB") return 1 ;; esac
  IFS=$TAB read -r f1 f2 f3 f4 f5 f6 fx <<EOF
$el
EOF
  [ -n "$f6" ] && [ -z "$fx" ] || return 1
  is_digits "$f1" 9 || return 1
  for ef in "$f2" "$f3" "$f4" "$f5"; do
    is_token "$ef" || return 1
  done
  [ ${#f6} -eq 8 ] || return 1
  case "$f6" in *[!0-9a-f]*) return 1 ;; esac
  [ "$(crc_hex "${el%"$TAB"*}")" = "$f6" ] || return 1
  [ "$f2" = INTENT ] || return 1
  E_KIND=$f3
  E_TARGET=$f4
  E_PRIOR=$f5
  return 0
}

add_entry() { # rank entry
  case $1 in
    0) B0="$2$NL$B0" ;;
    1) B1="$2$NL$B1" ;;
    2) B2="$2$NL$B2" ;;
    3) B3="$2$NL$B3" ;;
    4) B4="$2$NL$B4" ;;
    5) B5="$2$NL$B5" ;;
    6) B6="$2$NL$B6" ;;
  esac
}

collect() {
  first=1
  while IFS= read -r line; do
    if [ $first -eq 1 ]; then
      first=0
      parse_header "$line" && HDR_OK=1
      continue
    fi
    parse_entry "$line" || continue
    case "$E_KIND" in
      PROC) r=0 ;;
      ZRAM) r=1 ;;
      PKG_SUSPEND) r=2 ;;
      IME|A11Y) r=3 ;;
      USB) r=4 ;;
      NETTYPE) r=5 ;;
      RADIO|SETTING) r=6 ;;
      *) continue ;;
    esac
    add_entry $r "$E_KIND$TAB$E_TARGET$TAB$E_PRIOR"
  done < "$JOURNAL"
}

emit() {
  eo=$1
  shift
  for ea in "$@"; do
    eo="$eo$TAB$ea"
  done
  printf '%s\n' "$eo"
}

# Runs one fixed command; journal values only ever arrive as arguments.
run() {
  if [ "$MODE" = plan ]; then
    emit exec "$@"
    return 0
  fi
  "$@" >/dev/null 2>&1
}

attempt() {
  an=0
  while [ $an -lt 3 ]; do
    "$@" && return 0
    an=$((an + 1))
    [ "$MODE" = plan ] && return 1
    sleep 1
  done
  return 1
}

verify_setting() { # ns key expected
  [ "$MODE" = plan ] && return 0
  vn=0
  while [ $vn -lt 15 ]; do
    vv=$(settings get "$1" "$2" 2>/dev/null)
    [ -z "$vv" ] && vv=null
    [ "$vv" = "$3" ] && return 0
    vn=$((vn + 1))
    sleep 1
  done
  return 1
}

step_setting() { # ns key value
  if [ "$3" = null ]; then
    run settings delete "$1" "$2" || return 1
  else
    run settings put "$1" "$2" "$3" || return 1
  fi
  verify_setting "$1" "$2" "$3"
}

step_ime() {
  run ime set "$1" || return 1
  verify_setting secure default_input_method "$1"
}

step_radio() { # radio on|off
  case "$1" in
    wifi) if [ "$2" = on ]; then rv=enabled; else rv=disabled; fi; run cmd wifi set-wifi-enabled "$rv" ;;
    bluetooth) if [ "$2" = on ]; then rv=enable; else rv=disable; fi; run cmd bluetooth_manager "$rv" ;;
    nfc) if [ "$2" = on ]; then rv=enable; else rv=disable; fi; run svc nfc "$rv" ;;
    uwb) if [ "$2" = on ]; then rv=enable-uwb; else rv=disable-uwb; fi; run cmd uwb "$rv" ;;
    data) if [ "$2" = on ]; then rv=enable; else rv=disable; fi; run svc data "$rv" ;;
    *) return 1 ;;
  esac
}

proc_start() { # pid -> prints field 22 of /proc/<pid>/stat
  [ -r "/proc/$1/stat" ] || return 1
  ps_line=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  ps_line=${ps_line##*) }
  set -- $ps_line
  [ $# -ge 20 ] || return 1
  shift 19
  printf '%s' "$1"
}

step_kill() { # pid starttime
  if [ "$MODE" = plan ]; then
    emit kill "$1" "$2"
    return 0
  fi
  ks=$(proc_start "$1") || return 0
  [ "$ks" = "$2" ] || return 0
  kill -9 "$1" 2>/dev/null
  kn=0
  while [ $kn -lt 3 ]; do
    ks=$(proc_start "$1") || return 0
    [ "$ks" = "$2" ] || return 0
    sleep 1
    kn=$((kn + 1))
  done
  return 1
}

swap_has() { # device
  while read -r sw_dev sw_rest; do
    [ "$sw_dev" = "/dev/block/$1" ] && return 0
  done < /proc/swaps
  return 1
}

step_zram() { # device size,prio
  if [ "$MODE" = plan ]; then
    emit zram "$1" "$2"
    return 0
  fi
  swap_has "$1" && return 0
  zs=${2%%,*}
  zp=${2#*,}
  echo 1 > "/sys/block/$1/reset" 2>/dev/null
  echo "$zs" > "/sys/block/$1/disksize" 2>/dev/null || return 1
  mkswap "/dev/block/$1" >/dev/null 2>&1 || return 1
  case "$zp" in
    -*) swapon "/dev/block/$1" >/dev/null 2>&1 || return 1 ;;
    *) swapon -p "$zp" "/dev/block/$1" >/dev/null 2>&1 || return 1 ;;
  esac
  swap_has "$1"
}

fw_down() { # v4|v6
  if [ "$MODE" = plan ]; then
    emit fwdown "$1"
    return 0
  fi
  if [ "$1" = v4 ]; then ipt=iptables; else ipt=ip6tables; fi
  for fp in INPUT:aegis_in OUTPUT:aegis_out FORWARD:aegis_fwd; do
    fb=${fp%%:*}
    fc=${fp#*:}
    fn=0
    while [ $fn -lt 8 ] && "$ipt" -w -D "$fb" -j "$fc" >/dev/null 2>&1; do
      fn=$((fn + 1))
    done
    "$ipt" -w -F "$fc" >/dev/null 2>&1
    "$ipt" -w -X "$fc" >/dev/null 2>&1
  done
  fo=$("$ipt" -w -S 2>/dev/null) || return 1
  case "$fo" in *aegis_*) return 1 ;; esac
  return 0
}

# Returns 1 only when a valid step failed; invalid entries are skipped.
restore_entry() { # kind target prior
  rk=$1
  rt=$2
  rp=$3
  case "$rk" in
    SETTING)
      rns=${rt%%/*}
      rkey=${rt#*/}
      [ "$rns/$rkey" = "$rt" ] || return 0
      case "$rns" in global|secure|system) ;; *) return 0 ;; esac
      is_key "$rkey" || return 0
      attempt step_setting "$rns" "$rkey" "$rp" ;;
    A11Y)
      case "$rt" in enabled_accessibility_services|accessibility_enabled) ;; *) return 0 ;; esac
      attempt step_setting secure "$rt" "$rp" ;;
    IME)
      [ "$rt" = default_input_method ] || return 0
      if [ "$rp" = null ]; then
        attempt step_setting secure default_input_method null
      else
        case "$rp" in */*) ;; *) return 0 ;; esac
        case "$rp" in *[!A-Za-z0-9._/]*) return 0 ;; esac
        attempt step_ime "$rp"
      fi ;;
    RADIO)
      case "$rp" in on|off) ;; *) return 0 ;; esac
      case "$rt" in wifi|bluetooth|nfc|uwb|data) ;; *) return 0 ;; esac
      attempt step_radio "$rt" "$rp" ;;
    NETTYPE)
      case "$rt" in [0-3]) ;; *) return 0 ;; esac
      case "$rp" in ''|*[!01]*) return 0 ;; esac
      [ ${#rp} -le 32 ] || return 0
      attempt run cmd phone set-allowed-network-types-for-users -s "$rt" "$rp" ;;
    USB)
      [ "$rt" = functions ] || return 0
      case "$rp" in ''|*[!a-z0-9_,]*) return 0 ;; esac
      [ ${#rp} -le 64 ] || return 0
      if [ "$rp" = none ]; then
        attempt run svc usb setFunctions
      else
        attempt run svc usb setFunctions "$rp"
      fi ;;
    PKG_SUSPEND)
      [ "$rp" = 0 ] || return 0
      is_pkg "$rt" || return 0
      attempt run pm unsuspend --user 0 "$rt" ;;
    ZRAM)
      case "$rt" in zram[0-9]|zram[0-9][0-9]) ;; *) return 0 ;; esac
      rzs=${rp%%,*}
      rzp=${rp#*,}
      [ "$rzs,$rzp" = "$rp" ] || return 0
      is_digits "$rzs" 19 || return 0
      is_digits "${rzp#-}" 5 || return 0
      attempt step_zram "$rt" "$rp" ;;
    PROC)
      [ $SAME_BOOT -eq 1 ] || return 0
      rpid=${rt%%:*}
      rst=${rt#*:}
      [ "$rpid:$rst" = "$rt" ] || return 0
      is_digits "$rpid" 9 && is_digits "$rst" 19 || return 0
      attempt step_kill "$rpid" "$rst" ;;
    *) return 0 ;;
  esac
}

restore_all() {
  [ -f "$JOURNAL" ] || return 0
  collect
  [ $HDR_OK -eq 1 ] && [ "$HDR_BOOT" = "$CUR_BOOT" ] && SAME_BOOT=1
  for bk in "$B0" "$B1" "$B2" "$B3" "$B4" "$B5" "$B6"; do
    while IFS=$TAB read -r ek et ep; do
      [ -n "$ek" ] || continue
      restore_entry "$ek" "$et" "$ep" || FAILED=1
    done <<EOF
$bk
EOF
  done
  attempt fw_down v4 || FAILED=1
  attempt fw_down v6 || FAILED=1
}

# 0: the holder is gone (stale)  1: the holder is alive  2: no valid owner yet
lock_holder() {
  lo= ; lb= ; lt= ; lx=
  [ -r "$LOCKDIR/owner" ] && read -r lo lb lt lx < "$LOCKDIR/owner"
  case "$lo" in ''|*[!0-9]*) return 2 ;; esac
  [ "$lb" = "$CUR_BOOT" ] || return 0
  kill -0 "$lo" 2>/dev/null || return 0
  case "$lt" in ''|*[!0-9]*) return 1 ;; esac
  lc=$(proc_start "$lo") || return 1
  [ "$lc" = "$lt" ] || return 0
  return 1
}

lock_acquire() {
  ln_=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    lock_holder
    lr=$?
    if [ $lr -eq 0 ] || { [ $lr -eq 2 ] && [ $ln_ -ge 60 ]; }; then
      rm -f "$LOCKDIR/owner"
      rmdir "$LOCKDIR" 2>/dev/null
    fi
    ln_=$((ln_ + 1))
    [ $ln_ -ge $LOCK_WAIT ] && return 1
    sleep 1
  done
  echo "$$ $CUR_BOOT $(proc_start $$)" > "$LOCKDIR/owner"
  return 0
}

lock_release() {
  rm -f "$LOCKDIR/owner"
  rmdir "$LOCKDIR" 2>/dev/null
}

if [ "$MODE" = plan ] && [ $TESTRUN -eq 0 ]; then
  restore_all
  exit 0
fi

if [ "$MODE" = boot ]; then
  wn=0
  while [ "$(getprop sys.boot_completed)" != 1 ] && [ $wn -lt 300 ]; do
    sleep 2
    wn=$((wn + 1))
  done
fi

[ -f "$JOURNAL" ] || exit 0
[ $TESTRUN -eq 1 ] || CUR_BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
lock_acquire || exit 75
# Re-check under the lock: the daemon may have restored and removed it.
if [ ! -f "$JOURNAL" ]; then
  lock_release
  exit 0
fi
restore_all
if [ $FAILED -eq 0 ]; then
  rm -f "$JOURNAL"
  [ $TESTRUN -eq 1 ] || sync
  RC=0
else
  cmd notification post -t DialCrypt aegischat E500 >/dev/null 2>&1
  RC=75
fi
lock_release
exit $RC
