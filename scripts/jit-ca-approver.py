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

import ipaddress
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

TOKEN_TTL = 300                             # pending approval lifetime (s); matches jit-request TIMEOUT
MAX_DURATION_MIN = 8 * 60                   # hard cap on requested cert TTL
MAX_PUBKEY_BYTES = 2048                     # upper bound on single-line SSH pubkey length
MAX_REASON_CHARS = 200                      # upper bound on sanitized reason string
# PLACEHOLDER: list your target hostnames here; requests for anything not in
# this set are rejected before a notification is even sent.
TARGET_ALLOWLIST = {"target-host-1", "target-host-2"}

# Optional hypervisor self-reference guard (see contrib/proxmox-hypervisor-guard/).
# By default CURRENT_HOST_FILE does not exist on disk and these checks are a pure no-op.
CURRENT_HOST_FILE = "/run/jit-ca/current-hypervisor"
EVACUATE_CMD = "/usr/local/libexec/jit-ca-evacuate"
EVACUATE_TIMEOUT = 120

# Day-0 Tap-to-Enroll settings (airlock-enroll / action="enroll"):
ALLOWLIST_FILE = "/etc/jit-ca/target-allowlist.txt"
USER_CA_PUBKEY_FILE = "/etc/jit-ca/certs/ssh_user_ca_key.pub"
BIRTH_KEY_FILE = "/etc/jit-ca/secrets/birth_key"
BOOTSTRAP_USER = "root"
ANSIBLE_PLAYBOOK_CMD = "/usr/bin/ansible-playbook"
ONBOARD_PLAYBOOK = "/etc/jit-ca/ansible/onboard-target.yml"
BREAK_GLASS_ESCROW_DIR = "/etc/jit-ca/secrets/break-glass"
BREAK_GLASS_ESCROW_CMD = ""                 # optional Vaultwarden/Bitwarden/1Password CLI hook
ENROLL_TIMEOUT = 120
TARGET_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DURATION_RE = re.compile(r"^(\d+)([mh])$")
REQ_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
CTRL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\u202a-\u202e\u2066-\u2069]+")

with open(TOKEN_FILE) as fh:
    NTFY_TOKEN = fh.read().strip()

# token -> {"record": {...}, "expiry": epoch}
_pending = {}
_lock = threading.Lock()


# ---- helpers ----------------------------------------------------------------
def log(msg):
    print(f"[approver] {msg}", flush=True)


def target_principal(target):
    return f"{PRINCIPAL}@{target}" if target else PRINCIPAL


def current_hypervisor():
    """Return the hypervisor hostname hosting this CA VM if injected, else None."""
    if not CURRENT_HOST_FILE or not os.path.exists(CURRENT_HOST_FILE):
        return None
    try:
        with open(CURRENT_HOST_FILE) as fh:
            host = fh.read().strip()
        return host or None
    except OSError:
        return None


def can_evacuate():
    return bool(EVACUATE_CMD and os.path.isfile(EVACUATE_CMD) and os.access(EVACUATE_CMD, os.X_OK))


def is_target_allowlisted(target):
    if target in TARGET_ALLOWLIST:
        return True
    if ALLOWLIST_FILE and os.path.isfile(ALLOWLIST_FILE):
        try:
            with open(ALLOWLIST_FILE) as fh:
                for line in fh:
                    item = line.split("#", 1)[0].strip()
                    if item:
                        TARGET_ALLOWLIST.add(item)
        except OSError:
            pass
    return target in TARGET_ALLOWLIST


def persist_allowlisted_target(target):
    TARGET_ALLOWLIST.add(target)
    if not ALLOWLIST_FILE:
        return
    try:
        parent = os.path.dirname(ALLOWLIST_FILE)
        if parent and os.path.isdir(parent):
            existing = set()
            if os.path.isfile(ALLOWLIST_FILE):
                with open(ALLOWLIST_FILE) as fh:
                    existing = {ln.split("#", 1)[0].strip() for ln in fh if ln.strip()}
            if target not in existing:
                with open(ALLOWLIST_FILE, "a") as fh:
                    fh.write(f"{target}\n")
    except OSError as e:
        log(f"warning: could not persist {target} to {ALLOWLIST_FILE}: {e}")


def validate_target_ip(raw_ip):
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        return None
    try:
        ip_obj = ipaddress.ip_address(raw_ip.strip())
    except ValueError:
        return None
    if (
        not ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
    ):
        return None
    return str(ip_obj)


def enroll_target(rec):
    """Day-0 target enrollment:
    1. Generate fresh ed25519 break-glass keypair in a 0700 tempdir.
    2. Escrow private break-glass key (fail-closed if escrow fails!).
    3. Run ansible-playbook onboard-target.yml using BIRTH_KEY_FILE, installing CA trust,
       per-target principal, and replacing authorized_keys with ONLY break-glass.pub.
    4. Add target to TARGET_ALLOWLIST and return (bg_fingerprint, bg_pub).
    """
    target = rec["target"]
    target_ip = rec["target_ip"]
    if not USER_CA_PUBKEY_FILE or not os.path.isfile(USER_CA_PUBKEY_FILE):
        raise RuntimeError(f"missing USER_CA_PUBKEY_FILE at {USER_CA_PUBKEY_FILE}")
    if not BIRTH_KEY_FILE or not os.path.isfile(BIRTH_KEY_FILE):
        raise RuntimeError(f"missing BIRTH_KEY_FILE at {BIRTH_KEY_FILE}")
    if not ONBOARD_PLAYBOOK or not os.path.isfile(ONBOARD_PLAYBOOK):
        raise RuntimeError(f"missing ONBOARD_PLAYBOOK at {ONBOARD_PLAYBOOK}")

    with open(USER_CA_PUBKEY_FILE) as fh:
        ca_pubkey = fh.read().strip()
    birth_pubkey = ""
    if os.path.isfile(BIRTH_KEY_FILE + ".pub"):
        try:
            with open(BIRTH_KEY_FILE + ".pub") as fh:
                birth_pubkey = fh.read().strip()
        except OSError:
            pass

    tmpdir = tempfile.mkdtemp(prefix="jit-enroll-")
    os.chmod(tmpdir, 0o700)
    bg_key = os.path.join(tmpdir, "bg_key")
    bg_pub_file = bg_key + ".pub"
    inv_file = os.path.join(tmpdir, "inventory.json")
    try:
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
             "-C", f"{target}-break-glass", "-f", bg_key],
            check=True, capture_output=True, text=True, timeout=15,
        )
        with open(bg_key) as fh:
            bg_priv = fh.read()
        with open(bg_pub_file) as fh:
            bg_pub = fh.read().strip()

        fp_out = subprocess.run(
            ["ssh-keygen", "-lf", bg_pub_file],
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        fingerprint = fp_out.split()[1] if len(fp_out.split()) >= 2 else fp_out

        # Step 2: Fail-closed escrow of break-glass private key BEFORE touching target
        escrowed = False
        if BREAK_GLASS_ESCROW_CMD:
            subprocess.run(
                [BREAK_GLASS_ESCROW_CMD, target, target_ip],
                input=bg_priv, check=True, capture_output=True, text=True, timeout=30,
            )
            escrowed = True
        if BREAK_GLASS_ESCROW_DIR:
            os.makedirs(BREAK_GLASS_ESCROW_DIR, mode=0o700, exist_ok=True)
            priv_dest = os.path.join(BREAK_GLASS_ESCROW_DIR, f"{target}.id_ed25519")
            pub_dest = os.path.join(BREAK_GLASS_ESCROW_DIR, f"{target}.id_ed25519.pub")
            fd = os.open(priv_dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(bg_priv)
            with open(pub_dest, "w") as fh:
                fh.write(bg_pub + "\n")
            os.chmod(pub_dest, 0o644)
            escrowed = True
        if not escrowed:
            raise RuntimeError("no break-glass escrow destination configured")

        # Step 3: Write single-host JSON/YAML inventory & run onboard-target.yml over birth_key
        host_vars = {
            "ansible_host": target_ip,
            "ansible_user": BOOTSTRAP_USER,
            "ansible_ssh_private_key_file": BIRTH_KEY_FILE,
            "ansible_ssh_common_args": "-o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
            "jit_ca_target_name": target,
            "jit_ca_principal_user": PRINCIPAL,
            "jit_ca_user_ca_pubkey": ca_pubkey,
            "jit_ca_manage_authorized_keys": True,
            "jit_ca_break_glass_pubkey": bg_pub,
            "jit_ca_extra_authorized_keys": rec.get("extra_authorized_keys") or [],
            "jit_ca_purge_birth_pubkey": birth_pubkey,
        }
        if rec.get("principal_uid") is not None:
            host_vars["jit_ca_principal_uid"] = int(rec["principal_uid"])
        if rec.get("principals_dir"):
            host_vars["jit_ca_principals_dir"] = str(rec["principals_dir"])
        if rec.get("sshd_dropin_path"):
            host_vars["jit_ca_sshd_dropin_path"] = str(rec["sshd_dropin_path"])

        inv_data = {
            "all": {
                "children": {
                    "jit_ca_targets": {
                        "hosts": {
                            target: host_vars,
                        }
                    }
                }
            }
        }
        with open(inv_file, "w") as fh:
            json.dump(inv_data, fh, indent=2)

        env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING="False", ANSIBLE_RETRY_FILES_ENABLED="False")
        subprocess.run(
            [ANSIBLE_PLAYBOOK_CMD, "-i", inv_file, ONBOARD_PLAYBOOK, "--limit", target],
            env=env, check=True, capture_output=True, text=True, timeout=ENROLL_TIMEOUT,
        )
        persist_allowlisted_target(target)
        return fingerprint, bg_pub
    finally:
        for f in (bg_key, bg_pub_file, inv_file):
            try:
                os.remove(f)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def sanitize_reason(raw):
    if not isinstance(raw, str):
        return ""
    cleaned = CTRL_CHAR_RE.sub(" ", raw).strip()
    return cleaned[:MAX_REASON_CHARS]


def audit(action, rec, extra=""):
    principal = target_principal(rec.get("target"))
    line = (
        f"{datetime.now(timezone.utc).isoformat()} {action} "
        f"target={rec.get('target')} duration={rec.get('duration')} "
        f"principal={principal} req_id={rec.get('req_id')} "
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
    if not isinstance(d, str):
        return None
    m = DURATION_RE.match(d)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    minutes = n * 60 if unit == "h" else n
    if minutes < 1 or minutes > MAX_DURATION_MIN:
        return None
    return d


def sign_cert(pubkey_text, duration, target=None):
    """Sign pubkey_text for `duration` scoped to `target`; return (cert_text, valid_str)."""
    principal = target_principal(target)
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
            "--principal", principal, "--not-after", duration,
            principal, keyfile, "--force",
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
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return self._reply(400, "bad content-length")
        if length < 0 or length > 256:
            return self._reply(400, "invalid content-length")
        token = self.rfile.read(length).decode("utf-8", errors="replace").strip() if length else ""
        reap_expired()
        with _lock:
            entry = _pending.pop(token, None) if token else None

        if self.path == "/deny":
            if entry:
                audit("DENY", entry["record"])
                log(f"denied req_id={entry['record']['req_id']} "
                    f"target={entry['record'].get('target')}")
                # Publish nothing to TOPIC_CERT so an active human Deny is
                # indistinguishable from silence/timeout to the requesting agent.
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
        target = rec.get("target")
        cur_host = current_hypervisor()
        if cur_host and target == cur_host:
            if not can_evacuate():
                log(f"blocked self-referential sign for current hypervisor {target!r} (no evacuate script)")
                audit("SIGN_BLOCKED_SELF_HOST", rec, extra=f"hypervisor={json.dumps(cur_host)}")
                ntfy_publish(TOPIC_APPROVE,
                             f"Blocked: {target} is currently hosting jit-ca and no evacuate helper is installed.",
                             title="JIT self-reference blocked", tags=["no_entry"])
                return self._reply(409, "target is current hypervisor")
            try:
                subprocess.run([EVACUATE_CMD, target], check=True,
                               capture_output=True, text=True, timeout=EVACUATE_TIMEOUT)
            except (subprocess.SubprocessError, OSError) as e:
                err_msg = getattr(e, "stderr", "") or str(e)
                log(f"evacuation from {target!r} failed: {err_msg}")
                audit("EVACUATE_FAIL", rec, extra=f"err={json.dumps(err_msg[:200])}")
                ntfy_publish(TOPIC_APPROVE,
                             f"Evacuation from {target} FAILED — certificate NOT minted.",
                             title="JIT evacuation failed", tags=["rotating_light"])
                return self._reply(500, "evacuation failed")
            post_host = current_hypervisor()
            if post_host == target:
                log(f"evacuation script exited 0 but current_hypervisor is still {target!r}")
                audit("EVACUATE_FAIL", rec, extra='"still_on_target_hypervisor"')
                ntfy_publish(TOPIC_APPROVE,
                             f"Evacuation incomplete (still on {target}) — certificate NOT minted.",
                             title="JIT evacuation incomplete", tags=["rotating_light"])
                return self._reply(409, "still on target hypervisor")
            audit("EVACUATE", rec, extra=f"from={json.dumps(cur_host)} to={json.dumps(post_host)}")

        if rec.get("action") == "enroll":
            try:
                fingerprint, _ = enroll_target(rec)
            except (subprocess.SubprocessError, RuntimeError, OSError) as e:
                err_msg = getattr(e, "stderr", "") or getattr(e, "stdout", "") or str(e)
                log(f"enroll failed for {target!r}: {err_msg}")
                audit("ENROLL_FAIL", rec, extra=f"ip={json.dumps(rec.get('target_ip'))} err={json.dumps(err_msg[:200])}")
                ntfy_publish(TOPIC_APPROVE,
                             f"Enrollment FAILED for {target} ({rec.get('target_ip')}) — check airlock logs.",
                             title="Airlock enrollment error", tags=["rotating_light"])
                return self._reply(500, "enroll failed")

            ntfy_publish(TOPIC_CERT, json.dumps({
                "req_id": rec["req_id"],
                "enrolled": True,
                "target": target,
                "target_ip": rec.get("target_ip"),
                "fingerprint": fingerprint,
            }))
            audit("ENROLL", rec, extra=f"ip={json.dumps(rec.get('target_ip'))} bg_fp={json.dumps(fingerprint)}")
            ntfy_publish(TOPIC_APPROVE,
                         f"Enrolled & locked: {target} ({rec.get('target_ip')}). Break-glass: {fingerprint}",
                         title="Target enrolled in Airlock ✅", tags=["white_check_mark"])
            log(f"enrolled req_id={rec['req_id']} target={target} ip={rec.get('target_ip')} bg_fp={fingerprint}")
            return self._reply(200, "enrolled")

        try:
            cert_text, valid = sign_cert(rec["pubkey"], rec["duration"], target)
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
    if not isinstance(payload, str):
        log("dropping non-string request payload")
        return
    try:
        rec = json.loads(payload)
    except json.JSONDecodeError:
        log("dropping non-JSON request")
        return
    if not isinstance(rec, dict):
        log("dropping non-object JSON request")
        return

    req_id = rec.get("req_id")
    if not isinstance(req_id, str) or not REQ_ID_RE.match(req_id):
        log(f"rejecting request with missing/malformed req_id {req_id!r}")
        return

    action = rec.get("action", "sign")
    target = rec.get("target")
    raw_reason = rec.get("reason", "")

    if action == "enroll":
        if not isinstance(target, str) or not TARGET_NAME_RE.match(target):
            log(f"rejecting enroll request with invalid target hostname {target!r}")
            ntfy_publish(TOPIC_APPROVE,
                         f"Rejected enroll request: invalid hostname {target!r}.",
                         title="Airlock enroll rejected", tags=["no_entry"])
            return
        target_ip = validate_target_ip(rec.get("target_ip"))
        if not target_ip:
            log(f"rejecting enroll request for {target!r} with invalid/non-private IP {rec.get('target_ip')!r}")
            ntfy_publish(TOPIC_APPROVE,
                         f"Rejected enroll request for {target}: invalid/non-private IP {rec.get('target_ip')!r}.",
                         title="Airlock enroll rejected", tags=["no_entry"])
            return
        reason = sanitize_reason(raw_reason)
        enroll_rec = {
            "action": "enroll",
            "req_id": req_id,
            "target": target,
            "target_ip": target_ip,
            "duration": "enroll",
            "reason": reason,
        }
        token = secrets.token_urlsafe(32)
        with _lock:
            _pending[token] = {"record": enroll_rec, "expiry": time.time() + TOKEN_TTL}
        actions = [
            {"action": "http", "label": "Approve: Enroll & Lock", "url": f"{WEBHOOK_URL}/approve",
             "method": "POST", "body": token, "clear": True},
            {"action": "http", "label": "Deny", "url": f"{WEBHOOK_URL}/deny",
             "method": "POST", "body": token, "clear": True},
        ]
        ntfy_publish(
            TOPIC_APPROVE,
            f"Enroll {target} ({target_ip}): {reason}",
            title="Enroll new target in Airlock?",
            actions=actions,
            priority=5,
            tags=["key"],
        )
        log(f"enroll request req_id={req_id} target={target} ip={target_ip} -> approval sent")
        return

    pubkey = rec.get("pubkey", "")
    duration = validate_duration(rec.get("duration"))

    if not isinstance(target, str) or not is_target_allowlisted(target):
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
    if (
        not isinstance(pubkey, str)
        or len(pubkey) > MAX_PUBKEY_BYTES
        or CTRL_CHAR_RE.search(pubkey)
        or not pubkey.startswith(("ssh-", "ecdsa-", "sk-"))
    ):
        log("rejecting request with no/invalid pubkey")
        return

    reason = sanitize_reason(raw_reason)
    rec["req_id"] = req_id
    rec["duration"] = duration
    rec["reason"] = reason

    cur_host = current_hypervisor()
    approve_label = "Approve"
    title = "Agent wants SSH access"
    msg_body = f"{target} for {duration}: {reason}"
    if cur_host and target == cur_host:
        if not can_evacuate():
            log(f"rejecting request for current hypervisor {target!r} (no evacuate helper)")
            audit("REJECT_SELF_HOST", rec, extra=f"hypervisor={json.dumps(cur_host)}")
            ntfy_publish(TOPIC_APPROVE,
                         f"Rejected request for {target}: jit-ca is currently hosted on {target} and no evacuate helper is configured.",
                         title="JIT self-reference rejected", tags=["no_entry"])
            return
        approve_label = "Approve: Evacuate & Mint"
        title = f"Evacuate jit-ca from {target} & grant SSH?"
        msg_body = f"[Self-Host Guard: evacuate {target} -> peer first] {target} for {duration}: {reason}"

    token = secrets.token_urlsafe(32)
    with _lock:
        _pending[token] = {"record": rec, "expiry": time.time() + TOKEN_TTL}

    actions = [
        {"action": "http", "label": approve_label, "url": f"{WEBHOOK_URL}/approve",
         "method": "POST", "body": token, "clear": True},
        {"action": "http", "label": "Deny", "url": f"{WEBHOOK_URL}/deny",
         "method": "POST", "body": token, "clear": True},
    ]
    ntfy_publish(
        TOPIC_APPROVE,
        msg_body,
        title=title,
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
