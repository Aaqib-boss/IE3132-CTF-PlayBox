#!/usr/bin/env python3
"""Poll CTFd for correct Stage 5 submissions; on a new player's solve,
reset the Stage 6 VM to its clean snapshot and start it headless.

Runs on the machine that hosts VirtualBox (Windows), stdlib only.

Environment variables:
  CTFD_URL            default http://10.10.10.1:8000
  CTFD_TOKEN          admin access token (never commit it)
  STAGE5_CHALLENGE_ID numeric id of the Stage 5 challenge in CTFd
  STAGE6_VM           default Stage6-VM
  STAGE6_SNAPSHOT     default clean-state
  VBOXMANAGE          default C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe
  POLL_SECONDS        default 5

Flags:
  --dry-run           log what would happen, do not touch VirtualBox
  --trigger-existing  on first run, also act on solves that already exist
"""
import json, os, subprocess, sys, time
import urllib.request, urllib.error

CTFD_URL = os.environ.get("CTFD_URL", "http://10.10.10.1:8000").rstrip("/")
TOKEN = os.environ.get("CTFD_TOKEN", "")
CHAL_ID = os.environ.get("STAGE5_CHALLENGE_ID", "")
VM = os.environ.get("STAGE6_VM", "Stage6-VM")
SNAP = os.environ.get("STAGE6_SNAPSHOT", "clean-state")
VBOX = os.environ.get("VBOXMANAGE", r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
POLL = int(os.environ.get("POLL_SECONDS", "5"))
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".webhook_state.json")
DRY = "--dry-run" in sys.argv
TRIGGER_EXISTING = "--trigger-existing" in sys.argv


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def api(path):
    req = urllib.request.Request(
        CTFD_URL + path,
        headers={"Authorization": f"Token {TOKEN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def correct_solvers():
    """Return {user_id: first correct submission id} for the Stage 5 challenge."""
    out, page = {}, 1
    while True:
        d = api(f"/api/v1/submissions?challenge_id={CHAL_ID}&type=correct&page={page}")
        for s in d.get("data", []):
            uid = s.get("user_id")
            if uid is not None and uid not in out:
                out[uid] = s["id"]
        nxt = (d.get("meta", {}).get("pagination", {}) or {}).get("next")
        if not nxt:
            return out
        page = nxt


def vbox(*args):
    cmd = [VBOX, *args]
    log("run: " + " ".join(cmd))
    if DRY:
        return 0
    return subprocess.run(cmd).returncode


def reset_stage6():
    vbox("controlvm", VM, "poweroff")        # fails harmlessly if already off
    if not DRY:
        time.sleep(5)
    if vbox("snapshot", VM, "restore", SNAP) != 0:
        log("ERROR: snapshot restore failed")
        return False
    if vbox("startvm", VM, "--type", "headless") != 0:
        log("ERROR: VM start failed")
        return False
    log("Stage 6 reset and started")
    return True


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_state(done):
    with open(STATE, "w") as f:
        json.dump({"done_users": sorted(done)}, f)


def main():
    if not TOKEN or not CHAL_ID:
        sys.exit("Set CTFD_TOKEN and STAGE5_CHALLENGE_ID first.")
    st = load_state()
    if st is None:
        done = set() if TRIGGER_EXISTING else set(correct_solvers())
        save_state(done)
        log(f"first run: {len(done)} existing solver(s) marked as already handled")
    else:
        done = set(st["done_users"])
    log(f"watching challenge {CHAL_ID} on {CTFD_URL} (dry-run={DRY})")
    while True:
        try:
            for uid in correct_solvers():
                if uid not in done:
                    log(f"new Stage 5 solve by user {uid}")
                    if reset_stage6():
                        done.add(uid)
                        save_state(done)
        except (urllib.error.URLError, TimeoutError) as e:
            log(f"CTFd not reachable ({e}); retrying")
        time.sleep(POLL)


if __name__ == "__main__":
    main()