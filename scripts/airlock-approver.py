#!/usr/bin/env python3
"""airlock-approver — out-of-band tap-to-sign approval & attestation daemon for Airlock.

Runs on the Airlock host as the `step` user. Two jobs in one process:

  1. Subscribe to the ntfy `airlock-requests` topic. For each agent request
     (target, duration, reason, pubkey, optional approver) mint a single-use,
     short-lived challenge token, stash the *full* request under it server-side,
     and publish an actionable `airlock-approvals` (or per-approver
     `airlock-approvals-<approver>`) notification carrying Approve / Deny
     http-action buttons.

  2. Serve a tiny LAN webhook (/approve, /deny). When the designated approver
     (human or agent steward) approves, the webhook validates the token
     (single-use, unexpired), signs the request bound to that token with step-ca
     (stamping both the target principal and the approver identity), and
     publishes the signed cert back over the `airlock-certs` topic.

See REPLICATION-GUIDE.md (Section 5) and AIRLOCK-SPEC.md for design rationale.
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
# PLACEHOLDER: set to the LAN IP of your Airlock box (CA_HOST in the guide).
# NTFY_LOCAL and WEBHOOK_HOST both need this same IP — ntfy and the webhook
# are co-located on the Airlock box and the approver reaches the webhook over LAN.
NTFY_LOCAL = "http://10.0.0.10:8080"       # ntfy binds the LAN IP, not loopback
WEBHOOK_HOST = "10.0.0.10"                  # same as CA_HOST; approver POSTs here
WEBHOOK_PORT = 8081
WEBHOOK_URL = f"http://{WEBHOOK_HOST}:{WEBHOOK_PORT}"  # derived — do not edit separately

TOPIC_REQ = "airlock-requests"
TOPIC_APPROVE = "airlock-approvals"
TOPIC_CERT = "airlock-certs"

# Multi-approver & OPA pre-check configuration:
DEFAULT_APPROVER = "brian"
PER_APPROVER_TOPICS = False                 # when True, routes prompts to f"{TOPIC_APPROVE}-{approver}"
STAMP_APPROVER_PRINCIPAL = False            # when True, always stamps approved-by-<approver>@<target>
PRECHECK_MODE = "boundary_only"             # "boundary_only" | "silent_precheck"
OPA_PRECHECK_URL = ""                       # e.g. "http://127.0.0.1:8181/v1/data/airlock/allow"

TOKEN_FILE = "/etc/airlock/secrets/ntfy-approver-token"
PROVISIONER_PW = "/etc/airlock/secrets/provisioner_password"
ROOT_CA = "/etc/airlock/certs/root_ca.crt"
STEPPATH = "/etc/airlock"
PROVISIONER = "airlock-ssh"                 # PLACEHOLDER: must match provisioner name in ca.json
CA_URL = "https://localhost:9000"
PRINCIPAL = "airlock-admin"                 # PLACEHOLDER: SSH principal/username on target hosts
AUDIT_LOG = "/var/log/airlock/audit.log"

TOKEN_TTL = 300                             # pending approval lifetime (s); matches airlock-request TIMEOUT
MAX_DURATION_MIN = 8 * 60                   # hard cap on requested cert TTL
MAX_PUBKEY_BYTES = 2048                     # upper bound on single-line SSH pubkey length
MAX_REASON_CHARS = 200                      # upper bound on sanitized reason string
# PLACEHOLDER: list your target hostnames here; requests for anything not in
# this set are rejected before a notification is even sent.
TARGET_ALLOWLIST = {"target-host-1", "target-host-2"}

# Optional hypervisor self-reference guard (see contrib/proxmox-hypervisor-guard/).
# By default CURRENT_HOST_FILE does not exist on disk and these checks are a pure no-op.
CURRENT_HOST_FILE = "/run/airlock/current-hypervisor"
EVACUATE_CMD = "/usr/local/libexec/airlock-evacuate"
EVACUATE_TIMEOUT = 120

# Day-0 Tap-to-Enroll settings (airlock-enroll / action="enroll"):
ALLOWLIST_FILE = "/etc/airlock/target-allowlist.txt"
USER_CA_PUBKEY_FILE = "/etc/airlock/certs/ssh_user_ca_key.pub"
BIRTH_KEY_FILE = "/etc/airlock/secrets/birth_key"
BOOTSTRAP_USER = "root"
ANSIBLE_PLAYBOOK_CMD = "/usr/bin/ansible-playbook"
ONBOARD_PLAYBOOK = "/etc/airlock/ansible/onboard-target.yml"
BREAK_GLASS_ESCROW_DIR = "/etc/airlock/secrets/break-glass"
BREAK_GLASS_ESCROW_CMD = ""                 # optional Vaultwarden/Bitwarden/1Password CLI hook
ENROLL_TIMEOUT = 120
TARGET_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
APPROVER_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
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


def approver_principal(approver, target):
    return f"approved-by-{approver}@{target}" if target else f"approved-by-{approver}"


def approver_topic(approver=None):
    if PER_APPROVER_TOPICS and approver:
        return f"{TOPIC_APPROVE}-{approver}"
    return TOPIC_APPROVE


def validate_approver(raw_approver):
    if raw_approver is None or raw_approver == "":
        return DEFAULT_APPROVER, False
    if not isinstance(raw_approver, str):
        return None, True
    cleaned = raw_approver.strip()
    if not APPROVER_NAME_RE.match(cleaned):
        return None, True
    return cleaned, True


def check_opa_precheck(rec):
    """When PRECHECK_MODE == 'silent_precheck' and OPA_PRECHECK_URL is set, query OPA
    before paging the approver. Returns True if allowed, False if denied.
    When denied, Caller-Visible Silence is preserved (nothing published to TOPIC_CERT)
    to prevent a permission-enumeration oracle."""
    if PRECHECK_MODE != "silent_precheck" or not OPA_PRECHECK_URL:
        return True
    payload = json.dumps({
        "input": {
            "action": rec.get("action", "sign"),
            "req_id": rec.get("req_id"),
            "target": rec.get("target"),
            "approver": rec.get("approver", DEFAULT_APPROVER),
            "duration": rec.get("duration"),
            "reason": rec.get("reason", ""),
        }
    }).encode()
    req = urlrequest.Request(
        OPA_PRECHECK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            return bool(body.get("result") is True)
    except (HTTPError, URLError, OSError, ValueError) as e:
        log(f"OPA precheck error for target={rec.get('target')} approver={rec.get('approver')}: {e}")
        return False


def current_hypervisor():
    """Return the hypervisor hostname hosting this Airlock VM if injected, else None."""
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

    tmpdir = tempfile.mkdtemp(prefix="airlock-enroll-")
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

        # Step 3: Write single-host JSON inventory & run onboard-target.yml over birth_key
        host_vars = {
            "ansible_host": target_ip,
            "ansible_user": BOOTSTRAP_USER,
            "ansible_ssh_private_key_file": BIRTH_KEY_FILE,
            "ansible_ssh_common_args": "-o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
            "airlock_target_name": target,
            "airlock_principal_user": PRINCIPAL,
            "airlock_user_ca_pubkey": ca_pubkey,
            "airlock_manage_authorized_keys": True,
            "airlock_break_glass_pubkey": bg_pub,
            "airlock_extra_authorized_keys": rec.get("extra_authorized_keys") or [],
            "airlock_purge_birth_pubkey": birth_pubkey,
        }
        if rec.get("allowed_approvers"):
            host_vars["airlock_allowed_approvers"] = list(rec["allowed_approvers"])
        if rec.get("principal_uid") is not None:
            host_vars["airlock_principal_uid"] = int(rec["principal_uid"])
        if rec.get("principals_dir"):
            host_vars["airlock_principals_dir"] = str(rec["principals_dir"])
        if rec.get("sshd_dropin_path"):
            host_vars["airlock_sshd_dropin_path"] = str(rec["sshd_dropin_path"])

        inv_data = {
            "all": {
                "children": {
                    "airlock_targets": {
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
    approver = rec.get("approver", DEFAULT_APPROVER)
    line = (
        f"{datetime.now(timezone.utc).isoformat()} {action} "
        f"target={rec.get('target')} duration={rec.get('duration')} "
        f"principal={principal} approver={approver} req_id={rec.get('req_id')} "
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
    data = json.dumps(payload).encode()
    req = urlrequest.Request(
        f"{NTFY_LOCAL}/",
        data=data,
        headers={
            "Authorization": f"Bearer {NTFY_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            resp.read()
    except (HTTPError, URLError) as e:
        log(f"ntfy publish to {topic} failed: {e}")


def validate_duration(raw):
    if not isinstance(raw, str):
        return None
    m = DURATION_RE.match(raw.strip())
    if not m:
        return None
    val, unit = int(m.group(1)), m.group(2)
    minutes = val if unit == "m" else val * 60
    if minutes <= 0 or minutes > MAX_DURATION_MIN:
        return None
    return raw.strip()


def validate_pubkey(pk):
    if not isinstance(pk, str):
        return False
    s = pk.strip()
    if not s or len(s) > MAX_PUBKEY_BYTES:
        return False
    if "\n" in s or "\r" in s or CTRL_CHAR_RE.search(s):
        return False
    return s.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-"))


def sign_cert(pubkey_text, duration, target=None, approver=None, stamp_approver=False):
    """Sign pubkey_text for `duration` scoped to `target`; return (cert_text, valid_str)."""
    principal = target_principal(target)
    tmpdir = tempfile.mkdtemp(prefix="airlock-sign-", dir="/tmp")
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
            "--principal", principal,
        ]
        if (STAMP_APPROVER_PRINCIPAL or stamp_approver) and approver:
            cmd.extend(["--principal", approver_principal(approver, target)])
        cmd.extend([
            "--not-after", duration,
            principal, keyfile, "--force",
        ])
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
                rec = entry["record"]
                approver = rec.get("approver", DEFAULT_APPROVER)
                notify_topic = approver_topic(approver)
                audit("DENY", rec)
                log(f"denied req_id={rec['req_id']} target={rec.get('target')}")
                # Publish nothing to TOPIC_CERT so an active Deny is
                # indistinguishable from silence/timeout to the requesting agent.
                ntfy_publish(notify_topic,
                             f"Denied: {rec.get('target')} — {rec.get('reason')}",
                             title="Airlock request denied", tags=["x"])
            return self._reply(200, "denied")

        if self.path != "/approve":
            return self._reply(404, "not found")

        if not entry:
            log("approve with invalid/expired/used token")
            ntfy_publish(TOPIC_APPROVE,
                         "Approval failed: token expired, already used, or invalid.",
                         title="Airlock approval failed", tags=["warning"])
            return self._reply(410, "token invalid or expired")

        rec = entry["record"]
        target = rec.get("target")
        approver = rec.get("approver", DEFAULT_APPROVER)
        notify_topic = approver_topic(approver)

        if rec.get("action") == "enroll":
            try:
                fingerprint, _ = enroll_target(rec)
            except (subprocess.CalledProcessError, RuntimeError, OSError) as e:
                err_detail = getattr(e, "stderr", None) or str(e)
                log(f"enroll failed for {target!r}: {err_detail.strip()}")
                audit("ENROLL_FAIL", rec, extra=f"err={json.dumps(err_detail.strip()[:160])}")
                ntfy_publish(notify_topic,
                             f"Enrollment FAILED for {target} ({rec.get('target_ip')}) — check airlock logs.",
                             title="Airlock enrollment error", tags=["rotating_light"])
                return self._reply(500, "enroll failed")

            ntfy_publish(TOPIC_CERT, json.dumps({
                "req_id": rec["req_id"],
                "enrolled": True,
                "target": target,
                "target_ip": rec.get("target_ip"),
                "approver": approver,
                "fingerprint": fingerprint,
            }))
            audit("ENROLL", rec, extra=f"ip={json.dumps(rec.get('target_ip'))} bg_fp={json.dumps(fingerprint)}")
            ntfy_publish(notify_topic,
                         f"Enrolled & locked: {target} ({rec.get('target_ip')}). Break-glass: {fingerprint}",
                         title="Target enrolled in Airlock ✅", tags=["white_check_mark"])
            log(f"enrolled req_id={rec['req_id']} target={target} ip={rec.get('target_ip')} bg_fp={fingerprint}")
            return self._reply(200, "enrolled")

        cur_host = current_hypervisor()
        if cur_host and target == cur_host:
            if not can_evacuate():
                log(f"blocked self-referential sign for current hypervisor {target!r} (no evacuate script)")
                audit("SIGN_BLOCKED_SELF_HOST", rec, extra=f"hypervisor={json.dumps(cur_host)}")
                ntfy_publish(notify_topic,
                             f"Blocked: {target} is currently hosting airlock and no evacuate helper is installed.",
                             title="Airlock self-protection", tags=["octagonal_sign"])
                return self._reply(409, "cannot mint cert for current hypervisor without evacuation")
            try:
                subprocess.run(
                    [EVACUATE_CMD, target],
                    check=True, capture_output=True, text=True, timeout=EVACUATE_TIMEOUT,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                err = getattr(e, "stderr", "") or str(e)
                log(f"evacuation from {target!r} failed: {err.strip()}")
                audit("EVACUATE_FAIL", rec, extra=f"err={json.dumps(err.strip()[:120])}")
                ntfy_publish(notify_topic,
                             f"Evacuation from {target} failed; cert NOT minted.",
                             title="Airlock evacuation failed", tags=["rotating_light"])
                return self._reply(500, "evacuation failed")
            new_host = current_hypervisor()
            if new_host == target:
                log(f"evacuation script exited 0 but current_hypervisor is still {target!r}")
                audit("EVACUATE_FAIL", rec, extra='err="still on target hypervisor"')
                return self._reply(409, "still running on target hypervisor")
            audit("EVACUATE", rec, extra=f"from={target} to={new_host}")

        try:
            if rec.get("approver_explicit") or STAMP_APPROVER_PRINCIPAL:
                cert_text, valid = sign_cert(
                    rec["pubkey"],
                    rec["duration"],
                    target,
                    approver=approver,
                    stamp_approver=True,
                )
            else:
                cert_text, valid = sign_cert(rec["pubkey"], rec["duration"], target)
        except subprocess.CalledProcessError as e:
            log(f"sign failed: {e.stderr}")
            audit("SIGN_FAIL", rec, extra=f"err={e.stderr.strip()!r}")
            ntfy_publish(notify_topic,
                         f"Signing FAILED for {target} ({rec['req_id']}) — check airlock logs.",
                         title="Airlock error", tags=["rotating_light"])
            return self._reply(500, "sign failed")
        ntfy_publish(TOPIC_CERT, json.dumps({
            "req_id": rec["req_id"],
            "cert": cert_text,
            "valid": valid,
            "target": target,
            "approver": approver,
        }))
        audit("SIGN", rec, extra=valid)
        ntfy_publish(notify_topic,
                     f"Approved: {target} for {rec['duration']} ({valid}).",
                     title="SSH cert issued ✅", tags=["white_check_mark"])
        log(f"signed req_id={rec['req_id']} target={target} {valid}")
        return self._reply(200, "approved")
# ---- request subscriber -----------------------------------------------------
def handle_request(payload):
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

    approver, approver_explicit = validate_approver(rec.get("approver"))
    if approver is None:
        log(f"rejecting request with invalid approver {rec.get('approver')!r}")
        ntfy_publish(TOPIC_APPROVE,
                     f"Rejected request: invalid approver {rec.get('approver')!r}.",
                     title="Airlock request rejected", tags=["no_entry"])
        return

    action = rec.get("action", "sign")
    target = rec.get("target")
    raw_reason = rec.get("reason", "")
    notify_topic = approver_topic(approver)

    if action == "enroll":
        if not isinstance(target, str) or not TARGET_NAME_RE.match(target):
            log(f"rejecting enroll request with invalid target hostname {target!r}")
            ntfy_publish(notify_topic,
                         f"Rejected enroll request: invalid hostname {target!r}.",
                         title="Airlock enroll rejected", tags=["no_entry"])
            return
        target_ip = validate_target_ip(rec.get("target_ip"))
        if not target_ip:
            log(f"rejecting enroll request for {target!r} with invalid/non-private IP {rec.get('target_ip')!r}")
            ntfy_publish(notify_topic,
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
            "approver": approver,
            "approver_explicit": approver_explicit,
        }
        if not check_opa_precheck(enroll_rec):
            log(f"OPA precheck denied enroll req_id={req_id} target={target} approver={approver}")
            audit("PRECHECK_DENIED", enroll_rec)
            ntfy_publish(TOPIC_APPROVE,
                         f"OPA precheck blocked enroll request for {target} via approver {approver!r}.",
                         title="Airlock precheck blocked", tags=["shield"])
            return
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
            notify_topic,
            f"Enroll {target} ({target_ip}): {reason}",
            title="Enroll new target in Airlock?",
            actions=actions,
            priority=5,
            tags=["key"],
        )
        log(f"enroll request req_id={req_id} target={target} ip={target_ip} approver={approver} -> approval sent")
        return

    pubkey = rec.get("pubkey", "")
    duration = validate_duration(rec.get("duration"))

    if not isinstance(target, str) or not is_target_allowlisted(target):
        log(f"rejecting request for non-allowlisted target {target!r}")
        ntfy_publish(notify_topic,
                     f"Rejected request: unknown target {target!r}.",
                     title="Airlock request rejected", tags=["no_entry"])
        return
    if not duration:
        log(f"rejecting request with bad duration {rec.get('duration')!r}")
        ntfy_publish(notify_topic,
                     f"Rejected request for {target}: bad duration {rec.get('duration')!r}.",
                     title="Airlock request rejected", tags=["no_entry"])
        return
    if not validate_pubkey(pubkey):
        log("rejecting request with no/invalid pubkey")
        return

    reason = sanitize_reason(raw_reason)
    clean_rec = {
        "req_id": req_id,
        "target": target,
        "duration": duration,
        "reason": reason,
        "pubkey": pubkey.strip(),
        "approver": approver,
        "approver_explicit": approver_explicit,
    }

    if not check_opa_precheck(clean_rec):
        # Caller-Visible Silence: do NOT publish to TOPIC_CERT (zero permission oracle!)
        log(f"OPA precheck denied req_id={req_id} target={target} approver={approver}")
        audit("PRECHECK_DENIED", clean_rec)
        ntfy_publish(TOPIC_APPROVE,
                     f"OPA precheck blocked request for {target} via unauthorized approver {approver!r}.",
                     title="Airlock precheck blocked", tags=["shield"])
        return

    cur_host = current_hypervisor()
    needs_evac = bool(cur_host and target == cur_host)
    if needs_evac and not can_evacuate():
        log(f"rejecting request for current hypervisor {target!r} (no evacuate helper)")
        audit("REJECT_SELF_HOST", clean_rec)
        ntfy_publish(notify_topic,
                     f"Rejected request for {target}: Airlock is hosted on {target} and no evacuate helper is configured.",
                     title="Airlock self-protection", tags=["octagonal_sign"])
        return

    token = secrets.token_urlsafe(32)
    with _lock:
        _pending[token] = {"record": clean_rec, "expiry": time.time() + TOKEN_TTL}

    approve_label = "Approve: Evacuate & Mint" if needs_evac else "Approve"
    title_str = "Evacuate Airlock & grant SSH?" if needs_evac else "Grant SSH access?"
    body_prefix = f"[EVACUATE {target} -> peer] " if needs_evac else ""
    actions = [
        {"action": "http", "label": approve_label, "url": f"{WEBHOOK_URL}/approve",
         "method": "POST", "body": token, "clear": True},
        {"action": "http", "label": "Deny", "url": f"{WEBHOOK_URL}/deny",
         "method": "POST", "body": token, "clear": True},
    ]
    ntfy_publish(
        notify_topic,
        f"{body_prefix}{target} for {duration}: {reason}",
        title=title_str,
        actions=actions,
        priority=5,
        tags=["key"],
    )
    log(f"request req_id={req_id} target={target} dur={duration} approver={approver} -> approval sent")


def subscribe_loop():
    url = f"{NTFY_LOCAL}/{TOPIC_REQ}/json"
    while True:
        try:
            req = urlrequest.Request(
                url, headers={"Authorization": f"Bearer {NTFY_TOKEN}"}
            )
            with urlrequest.urlopen(req, timeout=90) as resp:
                log(f"subscribed to {TOPIC_REQ}")
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("event") == "message":
                        handle_request(ev.get("message", ""))
        except (HTTPError, URLError, TimeoutError, OSError) as e:
            log(f"subscribe reconnect after: {e}")
            time.sleep(3)


def reaper_loop():
    while True:
        time.sleep(30)
        now = time.time()
        with _lock:
            expired = [t for t, v in _pending.items() if v["expiry"] < now]
            for t in expired:
                rec = _pending.pop(t)["record"]
                audit("EXPIRE", rec)
                log(f"expired req_id={rec.get('req_id')} target={rec.get('target')}")


def main():
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    threading.Thread(target=subscribe_loop, daemon=True).start()
    threading.Thread(target=reaper_loop, daemon=True).start()
    srv = ThreadingHTTPServer((WEBHOOK_HOST, WEBHOOK_PORT), Handler)
    log(f"webhook listening on {WEBHOOK_HOST}:{WEBHOOK_PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
