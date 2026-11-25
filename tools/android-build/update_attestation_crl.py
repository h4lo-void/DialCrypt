#!/usr/bin/env python3
"""Fetches Google's Android Key Attestation CRL status feed and writes revoked
certificate serial numbers (one lowercase hex serial per line, deterministic order)
to app/src/main/res/raw/attestation_revoked.txt.
"""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.request

STATUS_URL = "https://android.googleapis.com/attestation/status"


def normalize_hex_serial(raw: str) -> str:
    s = raw.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.lstrip("0") or "0"
    if len(s) % 2 == 1:
        s = "0" + s
    int(s, 16)
    return s


def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    target = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) > 1
        else repo_root / "app" / "src" / "main" / "res" / "raw" / "attestation_revoked.txt"
    )

    req = urllib.request.Request(
        STATUS_URL,
        headers={"Accept": "application/json", "Cache-Control": "no-cache"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    entries = payload.get("entries", {})
    if not isinstance(entries, dict):
        raise ValueError("unexpected attestation status JSON structure")

    serials = sorted({normalize_hex_serial(k) for k in entries.keys() if k.strip()})
    lines = [
        "# Revoked Android Key Attestation certificate serial numbers (Google status feed).",
        "# Updated deterministically by tools/android-build/update_attestation_crl.py.",
        *serials,
        "",
    ]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(serials)} revoked serials to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
