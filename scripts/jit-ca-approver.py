#!/usr/bin/env python3
"""jit-ca-approver — the tap-to-sign approval daemon for the homelab SSH JIT-CA.

Runs on the CA host as the `step` user. Two jobs in one process:

  1. Subscribe to the ntfy `jit-requests` topic. For each agent request
     (target, duration, reason, pubkey) mint a single-use, short-lived token,
     stash the *full* request under it server-side, and publish an actionable
     `jit-approvals` notification carrying Approve / Deny http-action buttons.

  2. Serve a tiny LAN webhook (/approve, /deny). When you tap Approve on your
     phone, the ntfy app POSTs the token here. We validate (single-use,
     unexpired), sign exactly the request bound to that token with step-ca, and
     publish the signed cert back over the `jit-certs` topic. The agent never
     sees the token; it can ask but cannot approve.

See REPLICATION-GUIDE.md (Section 5) for the design rationale.
"""

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

# ---- config -----------------------------------------------------------------
# PLACEHOLDER: set to the LAN IP of your CA box (CA_HOST in the guide).
# NTFY_LOCAL and WEBHOOK_HOST both need this same IP — ntfy and the webhook
# are co-located on the CA box and the phone reaches the webhook over the LAN.
NTFY_LOCAL = "http://10.0.0.10:8080"       # ntfy binds the LAN IP, not loopback
WEBHOOK_HOST = "10.0.0.10"                  # same as CA_HOST; phone POSTs taps here
WEBHOOK_PORT = 8081
WEBHOOK_URL = f"http://{WEBHOOK_HOST}:{WEBHOOK_PORT}"  # derived — do not edit separately

TOPIC_REQ = "jit-requests"
TOPIC_APPROVE = "jit-approvals"
TOPIC_CERT = "jit-certs"

TOKEN_FILE = "/etc/jit-ca/secrets/ntfy-approver-token"
PROVISIONER_PW = "/etc/jit-ca/secrets/provisioner_password"
ROOT_CA = "/etc/jit-ca/certs/root_ca.crt"
STEPPATH = "/etc/jit-ca"
PROVISIONER = "jit-ssh"                     # PLACEHOLDER: must match the provisioner name in ca.json (set via step ca init --provisioner)
CA_URL = "https://localhost:9000"
PRINCIPAL = "agent"                         # PLACEHOLDER: SSH principal/username on all target hosts
AUDIT_LOG = "/var/log/jit-ca/audit.log"

TOKEN_TTL = 600                             # pending approval lifetime (s)
MAX_DURATION_MIN = 8 * 60                   # hard cap on requested cert TTL
# PLACEHOLDER: list your target hostnames here; requests for anything not in
# this set are rejected before a notification is even sent.
TARGET_ALLOWLIST = {"target-host-1", "target-host-2"}
DURATION_RE = re.compile(r"^(\d+)([mh])$")

with open(TOKEN_FILE) as fh:
    NTFY_TOKEN = fh.read().strip()

# token -> {"record": {...}, "expiry": epoch}
_pending = {}
_lock = threading.Lock()


# ---- helpers ----------------------------------------------------------------
def log(msg):
    print(f"[approver] {msg}", flush=True)


def audit(action, rec, extra=""):
    line = (
        f"{datetime.now(timezone.utc).isoformat()} {action} "
        f"target={rec.get('target')} duration={rec.get('duration')} "
        f"principal={PRINCIPAL} req_id={rec.get('req_id')} "
        f"reason={json.dumps(rec.get('reason',''))} {extra}\n"
    )
    try:
        with open(AUDIT_LOG, "a") as fh:
            fh.write(line)
    except OSError as e:
        log(f"audit write failed: {e}")


def ntfy_publish(topic, message, title=None, actions=None, tags=None, priority=None):
    payload = {"topic": topic, "message": message}
    if title:
        payload["title"] = title
    if actions:
        payload["actions"] = actions
    if tags:
        payload["tags"] = tags
    if priority:
        payload["priority"] = priority
    body = json.dumps(payload).encode()
    req = urlrequest.Request(
        NTFY_LOCAL + "/",
        data=body,
        headers={"Authorization": f"Bearer {NTFY_TOKEN}",
                 "Content-Type": "application/json"},
        method="POST",
    )
    try:
        urlrequest.urlopen(req, timeout=10).read()
    except (HTTPError, URLError) as e:
        log(f"publish to {topic} failed: {e}")


def validate_duration(d):
    m = DURATION_RE.match(d or "")
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    minutes = n * 60 if unit == "h" else n
    if minutes < 1 or minutes > MAX_DURATION_MIN:
        return None
    return d


def sign_cert(pubkey_text, duration):
    """Sign pubkey_text for `duration`; return (cert_text, valid_str)."""
    tmpdir = tempfile.mkdtemp(prefix="jit-sign-", dir="/tmp")
    keyfile = os.path.join(tmpdir, "k.pub")
    certfile = os.path.join(tmpdir, "k-cert.pub")
    try:
        with open(keyfile, "w") as fh:
            fh.write(pubkey_text.strip() + "\n")
        cmd = [
            "step", "ssh", "certificate", "--sign",
            "--provisioner", PROVISIONER,
            "--provisioner-password-file", PROVISIONER_PW,
            "--ca-url", CA_URL, "--root", ROOT_CA,
            "--principal", PRINCIPAL, "--not-after", duration,
            PRINCIPAL, keyfile, "--force",
        ]
        env = dict(os.environ, STEPPATH=STEPPATH)
        subprocess.run(cmd, env=env, check=True,
                       capture_output=True, text=True, timeout=30)
        with open(certfile) as fh:
            cert_text = fh.read().strip()
        valid = ""
        try:
            out = subprocess.run(["ssh-keygen", "-L", "-f", certfile],
                                 capture_output=True, text=True, check=True).stdout
            for ln in out.splitlines():
                if "Valid:" in ln:
                    valid = ln.strip()
        except subprocess.SubprocessError:
            pass
        return cert_text, valid
    finally:
        for f in (keyfile, certfile):
            try:
                os.remove(f)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def reap_expired():
    now = time.time()
    with _lock:
        dead = [t for t, v in _pending.items() if v["expiry"] < now]
        for t in dead:
            del _pending[t]


# ---- webhook ----------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _reply(self, code, msg):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(msg.encode())

    def log_message(self, *a):  # silence default stderr logging
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        token = self.rfile.read(length).decode().strip() if length else ""
        reap_expired()
        with _lock:
            entry = _pending.pop(token, None) if token else None

        if self.path == "/deny":
            if entry:
                audit("DENY", entry["record"])
                log(f"denied req_id={entry['record']['req_id']} "
                    f"target={entry['record'].get('target')}")
                # Generic close-out on jit-certs (the only topic the requester
                # can read) so it can stop polling early without learning this
                # was a deny rather than any other terminal non-issuance state.
                ntfy_publish(TOPIC_CERT,
                             json.dumps({"req_id": entry["record"]["req_id"],
                                         "cert": None}))
                ntfy_publish(TOPIC_APPROVE,
                             f"Denied: {entry['record'].get('target')} — "
                             f"{entry['record'].get('reason')}",
                             title="JIT request denied", tags=["x"])
            return self._reply(200, "denied")

        if self.path != "/approve":
            return self._reply(404, "not found")

        if not entry:
            log("approve with invalid/expired/used token")
            ntfy_publish(TOPIC_APPROVE,
                         "Approval failed: token expired, already used, or invalid.",
                         title="JIT approval failed", tags=["warning"])
            return self._reply(410, "token invalid or expired")

        rec = entry["record"]
        try:
            cert_text, valid = sign_cert(rec["pubkey"], rec["duration"])
        except subprocess.CalledProcessError as e:
            log(f"sign failed: {e.stderr}")
            audit("SIGN_FAIL", rec, extra=f"err={json.dumps((e.stderr or '')[:200])}")
            ntfy_publish(TOPIC_APPROVE,
                         f"Signing FAILED for {rec.get('target')} — check jit-ca logs.",
                         title="JIT signing error", tags=["rotating_light"])
            return self._reply(500, "sign failed")

        ntfy_publish(TOPIC_CERT, json.dumps({"req_id": rec["req_id"], "cert": cert_text}))
        audit("SIGN", rec, extra=f"valid={json.dumps(valid)}")
        ntfy_publish(TOPIC_APPROVE,
                     f"Signed: {rec.get('target')} for {rec.get('duration')}. {valid}",
                     title="JIT access granted ✅", tags=["white_check_mark"])
        log(f"signed req_id={rec['req_id']} target={rec.get('target')} {valid}")
        return self._reply(200, "approved")


# ---- request subscriber -----------------------------------------------------
def handle_request(payload):
    try:
        rec = json.loads(payload)
    except json.JSONDecodeError:
        log("dropping non-JSON request")
        return
    req_id = rec.get("req_id") or secrets.token_hex(8)
    rec["req_id"] = req_id
    target = rec.get("target")
    reason = rec.get("reason", "")
    pubkey = rec.get("pubkey", "")
    duration = validate_duration(rec.get("duration"))

    if target not in TARGET_ALLOWLIST:
        log(f"rejecting request for non-allowlisted target {target!r}")
        ntfy_publish(TOPIC_APPROVE,
                     f"Rejected request: unknown target {target!r}.",
                     title="JIT request rejected", tags=["no_entry"])
        return
    if not duration:
        log(f"rejecting bad duration {rec.get('duration')!r}")
        ntfy_publish(TOPIC_APPROVE,
                     f"Rejected request for {target}: bad duration "
                     f"{rec.get('duration')!r}.",
                     title="JIT request rejected", tags=["no_entry"])
        return
    if not pubkey.startswith(("ssh-", "ecdsa-", "sk-")):
        log("rejecting request with no/invalid pubkey")
        return

    rec["duration"] = duration
    token = secrets.token_urlsafe(32)
    with _lock:
        _pending[token] = {"record": rec, "expiry": time.time() + TOKEN_TTL}

    actions = [
        {"action": "http", "label": "Approve", "url": f"{WEBHOOK_URL}/approve",
         "method": "POST", "body": token, "clear": True},
        {"action": "http", "label": "Deny", "url": f"{WEBHOOK_URL}/deny",
         "method": "POST", "body": token, "clear": True},
    ]
    ntfy_publish(
        TOPIC_APPROVE,
        f"{target} for {duration}: {reason}",
        title="Agent wants SSH access",
        actions=actions,
        priority=5,  # ntfy JSON API: integer 1-5 (5=max), not the header-style "high"
        tags=["closed_lock_with_key"],
    )
    log(f"request req_id={req_id} target={target} dur={duration} -> approval sent")


def subscribe_loop():
    url = f"{NTFY_LOCAL}/{TOPIC_REQ}/json"
    while True:
        try:
            req = urlrequest.Request(
                url, headers={"Authorization": f"Bearer {NTFY_TOKEN}"})
            with urlrequest.urlopen(req, timeout=None) as stream:
                log(f"subscribed to {TOPIC_REQ}")
                for raw in stream:
                    line = raw.decode().strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("event") != "message":
                        continue
                    handle_request(ev.get("message", ""))
        except (HTTPError, URLError, OSError) as e:
            log(f"subscribe stream dropped ({e}); reconnecting in 5s")
            time.sleep(5)


def main():
    if not NTFY_TOKEN:
        log("no ntfy token; exiting")
        sys.exit(1)
    httpd = ThreadingHTTPServer((WEBHOOK_HOST, WEBHOOK_PORT), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    log(f"webhook listening on {WEBHOOK_URL} (/approve, /deny)")
    subscribe_loop()


if __name__ == "__main__":
    main()
