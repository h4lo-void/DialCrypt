#!/usr/bin/env bash
# One-shot build of the DialCrypt test artifacts on a build host with the Android toolchain.
# Run from anywhere; the script switches to the project root itself.
#
#   source ~/aegis-build/env.sh && bash tools/android-build/build.sh
#
# Output (all under out/):
#   out/aegischat-module.zip     root module (daemon + priv-app APK), zip root = module root
#   out/module/                  the unpacked module tree
#   out/app_cert_sha256.txt      SHA-256 of the APK signing certificate (for policy.conf)
#
# With AEGIS_TEST_NO_PIN=1 or AEGIS_FIELD_TEST=1 the script builds the fieldTest variant instead
# of release and names the zip out/aegischat-module-FIELDTEST.zip. Never install it for real use.
#
# The test signing key lives outside the project (~/aegis-build/keys) and its
# password is never printed.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

KEY_DIR=${AEGIS_KEY_DIR:-$HOME/aegis-build/keys}
KEYSTORE_FILE=$KEY_DIR/test-release.jks
PASS_FILE=$KEY_DIR/pass.txt
KEY_ALIAS_NAME=aegis-test
BUILD_TOOLS_VERSION=${AEGIS_BUILD_TOOLS_VERSION:-35.0.0}
ANDROID_API=30

step() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# --- variant ----------------------------------------------------------------
# The test switches only reach the fieldTest build type; Gradle refuses a release build while they are set.
if [ "${AEGIS_TEST_NO_PIN:-}" = "1" ] || [ "${AEGIS_FIELD_TEST:-}" = "1" ]; then
  FIELD_TEST=1
  GRADLE_TASK=:app:assemblePixelTitanFieldTest
  APK_REL=app/build/outputs/apk/pixelTitan/fieldTest/app-pixelTitan-fieldTest.apk
  ZIP_NAME=aegischat-module-FIELDTEST.zip
  printf 'FIELD TEST build (AEGIS_TEST_NO_PIN=%s AEGIS_FIELD_TEST=%s): not for real use\n' \
    "${AEGIS_TEST_NO_PIN:-}" "${AEGIS_FIELD_TEST:-}"
else
  FIELD_TEST=0
  GRADLE_TASK=:app:assemblePixelTitanRelease
  APK_REL=app/build/outputs/apk/pixelTitan/release/app-pixelTitan-release.apk
  ZIP_NAME=aegischat-module.zip
fi

# --- tool check -------------------------------------------------------------
for tool in cargo cargo-ndk keytool openssl zip unzip; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found; run: source ~/aegis-build/env.sh"
done
[ -n "${ANDROID_HOME:-}" ] || die "ANDROID_HOME is not set; run: source ~/aegis-build/env.sh"
[ -n "${ANDROID_NDK_HOME:-}" ] || die "ANDROID_NDK_HOME is not set; run: source ~/aegis-build/env.sh"
APKSIGNER=$ANDROID_HOME/build-tools/$BUILD_TOOLS_VERSION/apksigner
[ -x "$APKSIGNER" ] || die "apksigner not found at $APKSIGNER"

# --- a. JNI library ---------------------------------------------------------
step "a. aegiscall-jni (release, arm64-v8a)"
JNI_DIR=$ROOT/app/src/main/jniLibs
rm -rf "$JNI_DIR/arm64-v8a"
cargo ndk -t arm64-v8a -P "$ANDROID_API" -o "$JNI_DIR" build --release --locked -p aegiscall-jni
JNI_SO=$JNI_DIR/arm64-v8a/libaegiscall_jni.so
[ -f "$JNI_SO" ] || die "libaegiscall_jni.so was not produced at $JNI_SO"

# --- b. daemon --------------------------------------------------------------
step "b. aegiscalld (release, aarch64-linux-android)"
cargo ndk -t arm64-v8a -P "$ANDROID_API" build --release --locked -p aegiscalld
DAEMON_BIN=$ROOT/target/aarch64-linux-android/release/aegiscalld
[ -f "$DAEMON_BIN" ] || die "aegiscalld was not produced at $DAEMON_BIN"

# --- c. test signing key ----------------------------------------------------
step "c. test signing key"
if [ ! -f "$KEYSTORE_FILE" ]; then
  umask 077
  mkdir -p "$KEY_DIR"
  chmod 700 "$KEY_DIR"
  openssl rand -hex 24 > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
  if ! keytool -genkeypair -storetype PKCS12 -keystore "$KEYSTORE_FILE" \
      -storepass:file "$PASS_FILE" -alias "$KEY_ALIAS_NAME" \
      -keyalg RSA -keysize 4096 -validity 10950 \
      -dname "CN=DialCrypt Test Release, O=DialCrypt Test" >/dev/null 2>&1; then
    rm -f "$KEYSTORE_FILE" "$PASS_FILE"
    die "keytool could not create the test keystore"
  fi
  chmod 600 "$KEYSTORE_FILE"
  echo "created $KEYSTORE_FILE"
else
  echo "using existing $KEYSTORE_FILE"
fi
[ -s "$PASS_FILE" ] || die "$PASS_FILE is missing or empty; delete $KEYSTORE_FILE to regenerate the pair"

# --- d. signed APK ----------------------------------------------------------
step "d. $GRADLE_TASK"
AEGIS_KEYSTORE=$KEYSTORE_FILE
AEGIS_KEYSTORE_PASS=$(cat "$PASS_FILE")
AEGIS_KEY_ALIAS=$KEY_ALIAS_NAME
export AEGIS_KEYSTORE AEGIS_KEYSTORE_PASS AEGIS_KEY_ALIAS
bash ./gradlew --console=plain "$GRADLE_TASK"
APK=$ROOT/$APK_REL
[ -f "$APK" ] || die "signed APK not found at $APK"

# --- e. module --------------------------------------------------------------
step "e. module zip"
OUT=$ROOT/out
MODULE=$OUT/module
ZIP=$OUT/$ZIP_NAME
# Remove both zip names so a stale artifact of the other kind is never left next to this one.
rm -rf "$MODULE" "$ZIP" "$OUT/aegischat-module.zip" "$OUT/aegischat-module-FIELDTEST.zip"
mkdir -p "$OUT"
cp -R "$ROOT/magisk-module" "$MODULE"
rm -f "$MODULE/BUILD.md"
find "$MODULE" -name .DS_Store -exec rm -f {} +
mkdir -p "$MODULE/system/bin" "$MODULE/system/priv-app/DialCrypt"
install -m 0755 "$DAEMON_BIN" "$MODULE/system/bin/aegiscalld"
install -m 0644 "$APK" "$MODULE/system/priv-app/DialCrypt/DialCrypt.apk"
(cd "$MODULE" && zip -q -X -r "$ZIP" .)
MODULE_APK=$MODULE/system/priv-app/DialCrypt/DialCrypt.apk

# --- f. signing certificate hash --------------------------------------------
step "f. signing certificate"
"$APKSIGNER" verify --print-certs "$MODULE_APK" > "$OUT/.apksigner-certs.txt" 2>&1 \
  || { rm -f "$OUT/.apksigner-certs.txt"; die "apksigner verify failed for $MODULE_APK"; }
CERT_SHA=$(awk '/certificate SHA-256 digest:/ { print $NF; exit }' "$OUT/.apksigner-certs.txt" | tr 'A-F' 'a-f')
rm -f "$OUT/.apksigner-certs.txt"
printf '%s' "$CERT_SHA" | grep -Eq '^[0-9a-f]{64}$' || die "could not read a 64-hex certificate SHA-256 from apksigner"
printf '%s\n' "$CERT_SHA" > "$OUT/app_cert_sha256.txt"

if [ "$FIELD_TEST" = "1" ]; then
  printf '\nDONE: FIELD TEST BUILD (test switches on, never install on a phone in real use)\n'
else
  printf '\nDONE\n'
fi
printf 'APK:                %s\n' "$APK"
printf 'Module APK:         %s\n' "$MODULE_APK"
printf 'Daemon:             %s\n' "$MODULE/system/bin/aegiscalld"
printf 'Module zip:         %s\n' "$ZIP"
printf 'app_cert_sha256:    %s\n' "$CERT_SHA"
printf 'Hash file:          %s\n' "$OUT/app_cert_sha256.txt"
