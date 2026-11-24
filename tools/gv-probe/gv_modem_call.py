#!/usr/bin/env python3
"""Play a modem test WAV into a Google Voice call and fetch what the phone heard.

Runs on the Mac next to ~/gv-test/gv_call.py (the existing Google Voice harness).
  gv_modem_call.py <mic_48k.wav> <out_remote.wav> <seconds> [number]
Set GV_AGENT to the Bageo agent the phone is attached to, and BAGEO_TOKEN to its
calls-UI token when the agent requires one (it is never printed).
Exit code 0 = recording saved, 1 = no call record, 2 = the call could not be placed.
"""
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.expanduser("~/gv-test"))
import gv_call as g  # noqa: E402

TOKEN = os.environ.get("BAGEO_TOKEN", "")


def with_token(path):
    if not TOKEN:
        return path
    return path + ("&" if "?" in path else "?") + "token=" + TOKEN


_agent_get = g.agent_get
g.agent_get = lambda path: _agent_get(with_token(path))


def main():
    wav48, out, secs = sys.argv[1], sys.argv[2], float(sys.argv[3])
    number = sys.argv[4] if len(sys.argv) > 4 else g.TARGET
    from playwright.sync_api import sync_playwright
    shutil.copyfile(wav48, g.CURRENT)
    if g.active_calls():
        print("FAIL the agent already has a call in progress")
        return 2
    g.ensure_chrome()
    with sync_playwright() as pw:
        browser, page = g.voice_page(pw)
        t0 = time.time()
        answered, err = g.place_call(page, number)
        if not answered:
            print("FAIL place call:", err, g.shot(page, "fail"))
            g.hang_up(page)
            return 2
        print("answered %.1fs after dialing" % (answered - t0))
        while time.time() - answered < secs:
            if g.active_calls() == 0:
                print("the phone side ended the call after %.0fs" % (time.time() - answered))
                break
            time.sleep(2)
        print("hang up:", g.hang_up(page))
        try:
            browser.close()
        except Exception:
            pass
    rec = g.find_record(t0)
    if not rec:
        print("FAIL no agent call record")
        return 1
    print("record", rec["id"], "duration_s", rec.get("duration_s"), "events", rec.get("events"))
    url = g.AGENT + with_token("/calls/api/audio/%s/remote" % rec["id"])
    subprocess.run(["curl", "-s", "-m", "60", "-o", out, url])
    print("saved", out, os.path.getsize(out) if os.path.exists(out) else 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

