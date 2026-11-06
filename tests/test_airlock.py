#!/usr/bin/env python3
"""Unit test suite for airlock (scripts/airlock-approver.py, scripts/airlock-request, and configs).

Covers:
  1. Existing baseline security and operational claims (allowlist, duration cap,
     pubkey check, single-use tokens, expiry, approve/deny flows, SIGN_FAIL,
     audit logging, webhook routing, and agent CLI polling/filtering/timeout).
  2. New bugfixes & hardening from the 2026-11-01 peer review (AIRLOCK-01..AIRLOCK-05):
     - AIRLOCK-01: Per-target certificate principal (`agent@<target>`) + audit + guide docs.
     - AIRLOCK-02: `/deny` is silent on `airlock-certs` (agent-visible silence).
     - AIRLOCK-03: Input bounds/sanitization on `req_id`, `pubkey`, `reason`, and JSON types.
     - AIRLOCK-04: `TOKEN_TTL` aligned with `airlock-request` `TIMEOUT` (60s <= TOKEN_TTL <= 300s).
     - AIRLOCK-05: `ufw-rules.sh` scoping, `LogsDirectory=airlock`, repo hygiene.
"""

import importlib.machinery
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(os.environ.get("AIRLOCK_REPO", Path(__file__).resolve().parent.parent))
APPROVER_PATH = REPO_ROOT / "scripts" / "airlock-approver.py"
REQUEST_CLI_PATH = REPO_ROOT / "scripts" / "airlock-request"
UFW_SCRIPT_PATH = REPO_ROOT / "scripts" / "ufw-rules.sh"
SERVICE_UNIT_PATH = REPO_ROOT / "scripts" / "airlock-approver.service"
REP_GUIDE_PATH = REPO_ROOT / "REPLICATION-GUIDE.md"

SAMPLE_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDUMMYTESTKEY0000000000000000000000000000000 airlock-test"
SAMPLE_REQ_ID = "a1b2c3d4e5f60718"


def load_approver_module(token_file_path: str, audit_log_path: str):
    """Load scripts/airlock-approver.py with mocked TOKEN_FILE and AUDIT_LOG paths."""
    source = APPROVER_PATH.read_text()
    source, n1 = re.subn(
        r'^TOKEN_FILE\s*=.*$',
        f'TOKEN_FILE = {token_file_path!r}',
        source,
        count=1,
        flags=re.MULTILINE,
    )
    source, n2 = re.subn(
        r'^AUDIT_LOG\s*=.*$',
        f'AUDIT_LOG = {audit_log_path!r}',
        source,
        count=1,
        flags=re.MULTILINE,
    )
    assert n1 == 1 and n2 == 1, "Failed to patch TOKEN_FILE or AUDIT_LOG in airlock-approver.py"
    spec = importlib.util.spec_from_loader("airlock_approver", loader=None)
    mod = importlib.util.module_from_spec(spec)
    exec(compile(source, str(APPROVER_PATH), "exec"), mod.__dict__)
    return mod


def load_request_module():
    """Load scripts/airlock-request as a module without executing main()."""
    loader = importlib.machinery.SourceFileLoader("airlock_request", str(REQUEST_CLI_PATH))
    spec = importlib.util.spec_from_loader("airlock_request", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class FakeWebhookRequest:
    """Minimal harness to invoke Approver's BaseHTTPRequestHandler.do_POST and _reply."""

    def __init__(self, handler_cls, path: str, body: str):
        self.path = path
        self.headers = {"Content-Length": str(len(body.encode()))}
        self.rfile = io.BytesIO(body.encode())
        self.wfile = io.BytesIO()
        self.status_code = None
        self.response_headers = {}
        self._handler_cls = handler_cls
        self._reply = handler_cls._reply.__get__(self, handler_cls)

    def send_response(self, code):
        self.status_code = code

    def send_header(self, k, v):
        self.response_headers[k] = v

    def end_headers(self):
        pass

    def run(self):
        self._handler_cls.do_POST(self)
        return self.status_code, self.wfile.getvalue().decode()


class TestBaselineApproverClaims(unittest.TestCase):
    """Tests for capabilities already claimed by airlock v1."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.token_file = os.path.join(self.tmpdir.name, "ntfy_token")
        self.audit_file = os.path.join(self.tmpdir.name, "audit.log")
        Path(self.token_file).write_text("test-secret-token\n")
        self.approver = load_approver_module(self.token_file, self.audit_file)
        self.published = []

        def fake_publish(topic, message, title=None, actions=None, tags=None, priority=None):
            self.published.append({
                "topic": topic,
                "message": message,
                "title": title,
                "actions": actions,
                "tags": tags,
                "priority": priority,
            })

        self.approver.ntfy_publish = fake_publish

    def tearDown(self):
        self.tmpdir.cleanup()

    def _invoke_post(self, path: str, body: str):
        req = FakeWebhookRequest(self.approver.Handler, path, body)
        return req.run()

    def test_validate_duration_bounds(self):
        vd = self.approver.validate_duration
        self.assertEqual(vd("1m"), "1m")
        self.assertEqual(vd("30m"), "30m")
        self.assertEqual(vd("1h"), "1h")
        self.assertEqual(vd("8h"), "8h")
        self.assertEqual(vd("480m"), "480m")
        # Out of bounds or malformed
        self.assertIsNone(vd("0m"))
        self.assertIsNone(vd("481m"))
        self.assertIsNone(vd("9h"))
        self.assertIsNone(vd("-1h"))
        self.assertIsNone(vd("30s"))
        self.assertIsNone(vd("1d"))
        self.assertIsNone(vd(""))
        self.assertIsNone(vd(None))

    def test_rejects_non_json_payload(self):
        self.approver.handle_request("not valid json {{{")
        self.assertEqual(len(self.approver._pending), 0)
        cert_msgs = [m for m in self.published if m["topic"] == self.approver.TOPIC_CERT]
        self.assertEqual(len(cert_msgs), 0)

    def test_rejects_unknown_target_and_alerts_human(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "rogue-host-99",
            "duration": "1h",
            "reason": "test",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 0)
        self.assertEqual(len(self.published), 1)
        self.assertEqual(self.published[0]["topic"], self.approver.TOPIC_APPROVE)
        self.assertIn("unknown target", self.published[0]["message"])

    def test_rejects_bad_duration_and_alerts_human(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "24h",
            "reason": "too long",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 0)
        self.assertEqual(len(self.published), 1)
        self.assertEqual(self.published[0]["topic"], self.approver.TOPIC_APPROVE)
        self.assertIn("bad duration", self.published[0]["message"])

    def test_rejects_invalid_pubkey_prefix(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "bad key",
            "pubkey": "rsa-invalid-prefix AAAA...",
        })
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 0)

    def test_valid_request_queues_single_use_token_and_notifies_phone(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "30m",
            "reason": "check container logs",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 1)
        token = next(iter(self.approver._pending.keys()))
        self.assertEqual(len(self.published), 1)
        notif = self.published[0]
        self.assertEqual(notif["topic"], self.approver.TOPIC_APPROVE)
        self.assertEqual(notif["priority"], 5)
        self.assertEqual(len(notif["actions"]), 2)
        self.assertEqual(notif["actions"][0]["label"], "Approve")
        self.assertEqual(notif["actions"][0]["method"], "POST")
        self.assertTrue(notif["actions"][0]["url"].endswith("/approve"))
        self.assertEqual(notif["actions"][0]["body"], token)
        self.assertEqual(notif["actions"][1]["label"], "Deny")
        self.assertEqual(notif["actions"][1]["method"], "POST")
        self.assertTrue(notif["actions"][1]["url"].endswith("/deny"))
        self.assertEqual(notif["actions"][1]["body"], token)

    def test_approve_signs_cert_publishes_and_audits_and_consumes_token(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "deploy update",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        token = next(iter(self.approver._pending.keys()))
        self.published.clear()

        with mock.patch.object(
            self.approver,
            "sign_cert",
            side_effect=lambda *a, **kw: ("ssh-ed25519-cert-v01@openssh.com FAKECERT", "Valid: from A to B"),
        ):
            code, body = self._invoke_post("/approve", token)

        self.assertEqual(code, 200)
        self.assertEqual(body, "approved")
        self.assertEqual(len(self.approver._pending), 0)

        cert_msgs = [m for m in self.published if m["topic"] == self.approver.TOPIC_CERT]
        self.assertEqual(len(cert_msgs), 1)
        cert_payload = json.loads(cert_msgs[0]["message"])
        self.assertEqual(cert_payload["req_id"], SAMPLE_REQ_ID)
        self.assertIn("FAKECERT", cert_payload["cert"])

        audit_text = Path(self.audit_file).read_text()
        self.assertIn("SIGN", audit_text)
        self.assertIn(f"req_id={SAMPLE_REQ_ID}", audit_text)

        # Replay of the same token must fail with 410
        code2, _ = self._invoke_post("/approve", token)
        self.assertEqual(code2, 410)

    def test_expired_token_rejected_with_410(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "expire test",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        token = next(iter(self.approver._pending.keys()))
        self.approver._pending[token]["expiry"] = time.time() - 10
        self.published.clear()

        with mock.patch.object(self.approver, "sign_cert") as mock_sign:
            code, _ = self._invoke_post("/approve", token)
            mock_sign.assert_not_called()
        self.assertEqual(code, 410)
        self.assertEqual(len(self.approver._pending), 0)
        cert_msgs = [m for m in self.published if m["topic"] == self.approver.TOPIC_CERT]
        self.assertEqual(len(cert_msgs), 0)

    def test_deny_followed_by_approve_with_same_token_returns_410(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "deny then approve test",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        token = next(iter(self.approver._pending.keys()))

        with mock.patch.object(self.approver, "sign_cert") as mock_sign:
            code_deny, _ = self._invoke_post("/deny", token)
            code_approve, _ = self._invoke_post("/approve", token)
            mock_sign.assert_not_called()
        self.assertEqual(code_deny, 200)
        self.assertEqual(code_approve, 410)

    def test_concurrent_double_approve_signs_only_once(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "concurrency test",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        token = next(iter(self.approver._pending.keys()))

        barrier = threading.Barrier(2)
        codes = []

        def slow_sign(*args, **kwargs):
            time.sleep(0.05)
            return ("ssh-ed25519-cert-v01@openssh.com FAKECERT", "Valid: from A to B")

        def worker():
            barrier.wait()
            c, _ = self._invoke_post("/approve", token)
            codes.append(c)

        with mock.patch.object(self.approver, "sign_cert", side_effect=slow_sign) as mock_sign:
            t1 = threading.Thread(target=worker)
            t2 = threading.Thread(target=worker)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            self.assertEqual(mock_sign.call_count, 1)

        self.assertEqual(sorted(codes), [200, 410])

    def test_sign_cert_cleans_up_tempdir_on_success_and_failure(self):
        created_dirs = []

        def fake_ok_run(cmd, *args, **kwargs):
            if cmd[0] == "step":
                keyfile = next(a for a in cmd if a.endswith("k.pub"))
                created_dirs.append(Path(keyfile).parent)
                Path(keyfile.replace("k.pub", "k-cert.pub")).write_text("CERT-DATA\n")
                return mock.Mock(returncode=0, stdout="", stderr="")
            return mock.Mock(returncode=0, stdout="        Valid: from A to B\n", stderr="")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=fake_ok_run):
            cert, valid = self.approver.sign_cert(SAMPLE_PUBKEY, "1h")
        self.assertEqual(cert, "CERT-DATA")
        self.assertEqual(len(created_dirs), 1)
        self.assertFalse(created_dirs[0].exists(), "Tempdir must be cleaned up on success")

        failed_dirs = []

        def fake_fail_run(cmd, *args, **kwargs):
            keyfile = next(a for a in cmd if a.endswith("k.pub"))
            failed_dirs.append(Path(keyfile).parent)
            raise subprocess.CalledProcessError(1, cmd, stderr="step error")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=fake_fail_run):
            with self.assertRaises(subprocess.CalledProcessError):
                self.approver.sign_cert(SAMPLE_PUBKEY, "1h")
        self.assertEqual(len(failed_dirs), 1)
        self.assertFalse(failed_dirs[0].exists(), "Tempdir must be cleaned up even when step raises")

    def test_unknown_webhook_path_returns_404_and_deny_replay_is_noop(self):
        code, body = self._invoke_post("/unknown-endpoint", "some-token")
        self.assertEqual(code, 404)
        self.assertEqual(body, "not found")

        # Calling /deny with an invalid/already-used token returns 200 without publishing or auditing
        self.published.clear()
        code_deny, body_deny = self._invoke_post("/deny", "nonexistent-token")
        self.assertEqual(code_deny, 200)
        self.assertEqual(body_deny, "denied")
        self.assertEqual(len(self.published), 0)
        self.assertFalse(Path(self.audit_file).exists())

    def test_sign_failure_audits_sign_fail_and_returns_500(self):
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "ca down test",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        token = next(iter(self.approver._pending.keys()))

        err = subprocess.CalledProcessError(1, ["step"], stderr="step-ca connection refused")
        with mock.patch.object(self.approver, "sign_cert", side_effect=err):
            code, _ = self._invoke_post("/approve", token)

        self.assertEqual(code, 500)
        self.assertEqual(len(self.approver._pending), 0)
        audit_text = Path(self.audit_file).read_text()
        self.assertIn("SIGN_FAIL", audit_text)


class TestBaselineAgentCli(unittest.TestCase):
    """Tests for scripts/airlock-request agent-side CLI."""

    def test_airlock_request_filters_by_req_id_and_writes_cert(self):
        req_mod = load_request_module()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            req_mod.TOKEN_FILE = tmp_path / "token"
            req_mod.TOKEN_FILE.write_text("agent-token\n")
            req_mod.KEY = tmp_path / "ssh" / "agent_key"
            req_mod.CERT = tmp_path / "ssh" / "agent_key-cert.pub"
            req_mod.KEY.parent.mkdir(parents=True, exist_ok=True)
            req_mod.KEY.write_text("PRIVATE")
            req_mod.KEY.with_suffix(".pub").write_text(SAMPLE_PUBKEY + "\n")

            fixed_req_id = "deadbeef12345678"

            def fake_urlopen(request_obj, timeout=15):
                url = request_obj.full_url
                if url.endswith("/"):
                    return io.BytesIO(b'{"id":"msg1"}')
                lines = [
                    json.dumps({"event": "message", "message": json.dumps({"req_id": "other000", "cert": "WRONG"})}),
                    json.dumps({"event": "message", "message": json.dumps({"req_id": fixed_req_id, "cert": "VALID-CERT-DATA"})}),
                ]
                return io.BytesIO(("\n".join(lines) + "\n").encode())

            with mock.patch.object(req_mod.secrets, "token_hex", return_value=fixed_req_id), \
                 mock.patch.object(req_mod.urlrequest, "urlopen", side_effect=fake_urlopen), \
                 mock.patch.object(req_mod.subprocess, "run") as mock_run, \
                 mock.patch.object(sys, "argv", ["airlock-request", "target-host-1", "1h", "test reason"]):
                mock_run.return_value = mock.Mock(stdout="        Valid: from 2026-11-02T09:00:00 to 2026-11-02T10:00:00\n")
                req_mod.main()

            self.assertTrue(req_mod.CERT.exists())
            self.assertEqual(req_mod.CERT.read_text().strip(), "VALID-CERT-DATA")

    def test_airlock_request_times_out_with_exit_code_2(self):
        req_mod = load_request_module()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            req_mod.TOKEN_FILE = tmp_path / "token"
            req_mod.TOKEN_FILE.write_text("agent-token\n")
            req_mod.KEY = tmp_path / "ssh" / "agent_key"
            req_mod.CERT = tmp_path / "ssh" / "agent_key-cert.pub"
            req_mod.KEY.parent.mkdir(parents=True, exist_ok=True)
            req_mod.KEY.write_text("PRIVATE")
            req_mod.KEY.with_suffix(".pub").write_text(SAMPLE_PUBKEY + "\n")
            req_mod.TIMEOUT = 0  # Immediate timeout

            def fake_urlopen(request_obj, timeout=15):
                return io.BytesIO(b"")

            with mock.patch.object(req_mod.urlrequest, "urlopen", side_effect=fake_urlopen), \
                 mock.patch.object(sys, "argv", ["airlock-request", "target-host-1", "1h", "timeout test"]):
                with self.assertRaises(SystemExit) as ctx:
                    req_mod.main()
                self.assertEqual(ctx.exception.code, 2)


class TestNewReviewFixes(unittest.TestCase):
    """Tests for AIRLOCK-01 through AIRLOCK-05 surfaced by the 2026-11-01 peer review."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.token_file = os.path.join(self.tmpdir.name, "ntfy_token")
        self.audit_file = os.path.join(self.tmpdir.name, "audit.log")
        Path(self.token_file).write_text("test-secret-token\n")
        self.approver = load_approver_module(self.token_file, self.audit_file)
        self.published = []

        def fake_publish(topic, message, title=None, actions=None, tags=None, priority=None):
            self.published.append({
                "topic": topic,
                "message": message,
                "title": title,
                "actions": actions,
                "tags": tags,
                "priority": priority,
            })

        self.approver.ntfy_publish = fake_publish

    def tearDown(self):
        self.tmpdir.cleanup()

    def _invoke_post(self, path: str, body: str):
        req = FakeWebhookRequest(self.approver.Handler, path, body)
        return req.run()

    def test_airlock01_sign_cert_scopes_principal_per_target(self):
        """AIRLOCK-01: Each target gets a distinct '<PRINCIPAL>@<target>' in --principal, positional key ID, and audit log."""
        self.approver.TARGET_ALLOWLIST = {"target-host-1", "target-host-2"}
        captured_step_cmds = []

        def fake_run(cmd, *args, **kwargs):
            if cmd[0] == "step":
                captured_step_cmds.append(list(cmd))
                keyfile = next(a for a in cmd if a.endswith("k.pub"))
                certfile = keyfile.replace("k.pub", "k-cert.pub")
                Path(certfile).write_text("CERT-FOR-TARGET\n")
                return mock.Mock(returncode=0, stdout="", stderr="")
            return mock.Mock(returncode=0, stdout="Valid: from now to later\n", stderr="")

        for idx, target in enumerate(("target-host-1", "target-host-2"), start=1):
            payload = json.dumps({
                "req_id": f"a1b2c3d4e5f6070{idx}",
                "target": target,
                "duration": "1h",
                "reason": "target scope check",
                "pubkey": SAMPLE_PUBKEY,
            })
            self.approver.handle_request(payload)
            token = next(iter(self.approver._pending.keys()))

            with mock.patch.object(self.approver.subprocess, "run", side_effect=fake_run):
                code, _ = self._invoke_post("/approve", token)

            self.assertEqual(code, 200)
            step_cmd = captured_step_cmds[-1]
            p_idx = step_cmd.index("--principal")
            signed_principal = step_cmd[p_idx + 1]
            expected_principal = f"{self.approver.PRINCIPAL}@{target}"
            self.assertEqual(
                signed_principal,
                expected_principal,
                f"Expected exact target-scoped --principal {expected_principal!r}, got {signed_principal!r}",
            )
            keyfile_idx = next(i for i, a in enumerate(step_cmd) if a.endswith("k.pub"))
            self.assertEqual(
                step_cmd[keyfile_idx - 1],
                expected_principal,
                f"Expected positional key-id {expected_principal!r}, got {step_cmd[keyfile_idx - 1]!r}",
            )

        audit_text = Path(self.audit_file).read_text()
        logged_principals = re.findall(r"\bprincipal=(\S+)", audit_text)
        self.assertIn("airlock-admin@target-host-1", logged_principals)
        self.assertIn(f"{self.approver.PRINCIPAL}@target-host-2", logged_principals)

        # Ensure REPLICATION-GUIDE.md documents AuthorizedPrincipalsFile with per-target principal
        guide_text = REP_GUIDE_PATH.read_text()
        self.assertRegex(guide_text, r"AuthorizedPrincipalsFile\s+/etc/ssh/airlock_principals/%u")
        self.assertIn("agent@", guide_text)

    def test_airlock02_deny_is_silent_on_cert_topic(self):
        """AIRLOCK-02: /deny must NOT publish to TOPIC_CERT so Deny is indistinguishable from silence to the agent."""
        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "test deny silence",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        token = next(iter(self.approver._pending.keys()))
        self.published.clear()

        code, body = self._invoke_post("/deny", token)
        self.assertEqual(code, 200)
        self.assertEqual(body, "denied")

        # Audit log and human approval channel MUST record the denial:
        audit_text = Path(self.audit_file).read_text()
        self.assertIn("DENY", audit_text)
        approve_topic_msgs = [m for m in self.published if m["topic"] == self.approver.TOPIC_APPROVE]
        self.assertEqual(len(approve_topic_msgs), 1)

        # Agent-readable TOPIC_CERT must receive ZERO messages on /deny:
        cert_topic_msgs = [m for m in self.published if m["topic"] == self.approver.TOPIC_CERT]
        self.assertEqual(
            len(cert_topic_msgs),
            0,
            f"Expected 0 messages on {self.approver.TOPIC_CERT} upon /deny, got {cert_topic_msgs}",
        )

    def test_airlock03_rejects_missing_or_malformed_req_id_and_bad_json_types(self):
        """AIRLOCK-03a: Missing, non-hex, or injected req_id and non-dict JSON must be rejected cleanly."""
        for non_dict in ("[]", "null", "123", '"just-a-string"'):
            with self.subTest(non_dict=non_dict):
                self.approver.handle_request(non_dict)
                self.assertEqual(len(self.approver._pending), 0)

        # Non-string field values must not crash handle_request
        self.approver.handle_request(json.dumps({
            "req_id": 12345,
            "target": "target-host-1",
            "duration": 60,
            "reason": None,
            "pubkey": None,
        }))
        self.assertEqual(len(self.approver._pending), 0)

        bad_req_ids = [
            None,
            "",
            "short",
            "g1b2c3d4e5f60718",           # non-hex 'g'
            "a1b2c3d4e5f60718\nSIGN",     # newline injection
            "a" * 80,                     # overly long
        ]
        for bad_id in bad_req_ids:
            with self.subTest(bad_id=bad_id):
                self.approver._pending.clear()
                body = {
                    "target": "target-host-1",
                    "duration": "1h",
                    "reason": "req_id validation check",
                    "pubkey": SAMPLE_PUBKEY,
                }
                if bad_id is not None:
                    body["req_id"] = bad_id
                self.approver.handle_request(json.dumps(body))
                self.assertEqual(
                    len(self.approver._pending),
                    0,
                    f"Approver must reject malformed req_id={bad_id!r}",
                )

        # Positive control: valid 16-char hex req_id is still accepted
        self.approver.handle_request(json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "positive control",
            "pubkey": SAMPLE_PUBKEY,
        }))
        self.assertEqual(len(self.approver._pending), 1)

    def test_airlock03_rejects_oversized_or_multiline_pubkey(self):
        """AIRLOCK-03b: Oversized (>2048B) or multiline/control-char pubkeys must be rejected."""
        bad_keys = [
            "ssh-ed25519 " + ("A" * 3000),
            SAMPLE_PUBKEY + "\nssh-ed25519 AAAA_injected",
            SAMPLE_PUBKEY + "\rssh-ed25519 AAAA_injected",
            SAMPLE_PUBKEY + "\x00injected",
        ]
        for idx, bad_key in enumerate(bad_keys):
            with self.subTest(idx=idx):
                self.approver._pending.clear()
                self.approver.handle_request(json.dumps({
                    "req_id": SAMPLE_REQ_ID,
                    "target": "target-host-1",
                    "duration": "1h",
                    "reason": "key bounds check",
                    "pubkey": bad_key,
                }))
                self.assertEqual(len(self.approver._pending), 0)

    def test_airlock03_sanitizes_spoofed_and_overlong_reason(self):
        """AIRLOCK-03c: Reason with newlines/control chars or >200 chars must be queued with a sanitized reason in record, notification, and audit log."""
        spoofed_reason = "harmless check\n\r\x00\x1b\u2028\u202eAPPROVED: root@production " + ("x" * 250)
        self.approver.handle_request(json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": spoofed_reason,
            "pubkey": SAMPLE_PUBKEY,
        }))
        self.assertEqual(len(self.approver._pending), 1, "Request with spoofed/long reason should be sanitized and queued")
        self.assertEqual(len(self.published), 1)

        msg = self.published[0]["message"]
        for ch in ("\n", "\r", "\x00", "\x1b", "\u2028", "\u202e"):
            self.assertNotIn(ch, msg, f"Control char {ch!r} reached phone notification")
        self.assertLessEqual(len(msg), 260, "Notification message with truncated reason exceeds expected cap")

        token, entry = next(iter(self.approver._pending.items()))
        stored_reason = entry["record"]["reason"]
        for ch in ("\n", "\r", "\x00", "\x1b", "\u2028", "\u202e"):
            self.assertNotIn(ch, stored_reason, f"Control char {ch!r} stored in pending record")
        self.assertLessEqual(len(stored_reason), 200, "Stored reason exceeds 200 chars")

        self._invoke_post("/deny", token)
        audit_lines = Path(self.audit_file).read_text().splitlines()
        self.assertEqual(len(audit_lines), 1)
        self.assertNotIn("\\n", audit_lines[0], "Sanitized reason in audit log should not contain embedded newline")

    def test_airlock04_token_ttl_matches_cli_timeout(self):
        """AIRLOCK-04: TOKEN_TTL must be between 60s and airlock-request TIMEOUT (300s)."""
        req_mod = load_request_module()
        self.assertGreaterEqual(self.approver.TOKEN_TTL, 60)
        self.assertLessEqual(
            self.approver.TOKEN_TTL,
            req_mod.TIMEOUT,
            f"TOKEN_TTL ({self.approver.TOKEN_TTL}s) exceeds CLI TIMEOUT ({req_mod.TIMEOUT}s)",
        )

    def test_airlock05_ufw_systemd_and_repo_hygiene(self):
        """AIRLOCK-05: ufw-rules.sh scopes SSH + VPN 8080, service sets LogsDirectory=airlock, no verdict artifact."""
        ufw_text = UFW_SCRIPT_PATH.read_text()
        self.assertNotIn("ufw allow 22/tcp", ufw_text, "SSH on CA host should be subnet-scoped, not open to any")
        self.assertRegex(ufw_text, r'ufw allow from "\$LAN_SUBNET" to any port 22')
        self.assertRegex(ufw_text, r'ufw allow from "\$VPN_SUBNET" to any port 8080')

        service_text = SERVICE_UNIT_PATH.read_text()
        self.assertIn("LogsDirectory=airlock", service_text)

        verdict_file = REPO_ROOT / ".adjudication-verdict.json"
        self.assertFalse(verdict_file.exists(), ".adjudication-verdict.json should be removed from repo root")

    def test_airlock06_hypervisor_guard_is_noop_by_default(self):
        """AIRLOCK-06a: When CURRENT_HOST_FILE does not exist, current_hypervisor() is None and normal requests work unchanged."""
        self.approver.CURRENT_HOST_FILE = os.path.join(self.tmpdir.name, "nonexistent-current-hypervisor")
        self.assertIsNone(self.approver.current_hypervisor())

        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "default noop check",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 1)
        self.assertEqual(self.published[0]["actions"][0]["label"], "Approve")

    def test_airlock06_hypervisor_guard_rejects_self_target_when_no_evacuate_helper(self):
        """AIRLOCK-06b: If target == current_hypervisor and no evacuate helper exists, request and approve both fail closed."""
        host_file = Path(self.tmpdir.name) / "current-hypervisor"
        host_file.write_text("target-host-1\n")
        self.approver.CURRENT_HOST_FILE = str(host_file)
        self.approver.EVACUATE_CMD = os.path.join(self.tmpdir.name, "no-such-evacuate")

        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "attempt self mutation",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 0, "Self-target without evacuate helper must be rejected at request time")
        audit_text = Path(self.audit_file).read_text()
        self.assertIn("REJECT_SELF_HOST", audit_text)

        # Even if a token were queued while on peer host and the VM migrated onto target-host-1 before /approve:
        host_file.write_text("target-host-2\n")
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 1)
        token = next(iter(self.approver._pending.keys()))

        # Now VM is on target-host-1 when /approve is tapped:
        host_file.write_text("target-host-1\n")
        code, body = self._invoke_post("/approve", token)
        self.assertEqual(code, 409)
        self.assertIn("SIGN_BLOCKED_SELF_HOST", Path(self.audit_file).read_text())

    def test_airlock06_hypervisor_guard_evacuates_then_signs_and_fails_closed_if_stuck(self):
        """AIRLOCK-06c: With EVACUATE_CMD present, Approve evacuates first and only signs once current_hypervisor != target."""
        host_file = Path(self.tmpdir.name) / "current-hypervisor"
        host_file.write_text("target-host-1\n")
        evac_script = Path(self.tmpdir.name) / "mock-evacuate.sh"
        evac_script.write_text("#!/bin/sh\nexit 0\n")
        evac_script.chmod(0o755)

        self.approver.CURRENT_HOST_FILE = str(host_file)
        self.approver.EVACUATE_CMD = str(evac_script)

        payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "1h",
            "reason": "hypervisor kernel upgrade",
            "pubkey": SAMPLE_PUBKEY,
        })
        self.approver.handle_request(payload)
        self.assertEqual(len(self.approver._pending), 1)
        self.assertEqual(self.published[-1]["actions"][0]["label"], "Approve: Evacuate & Mint")
        token = next(iter(self.approver._pending.keys()))

        # Case 1: Evacuation runs and updates current-hypervisor to target-host-2
        def fake_run(cmd, *a, **kw):
            if cmd[0] == str(evac_script):
                host_file.write_text("target-host-2\n")
                return subprocess.CompletedProcess(cmd, 0, stdout="migrated", stderr="")
            if cmd[:3] == ["step", "ssh", "certificate"]:
                certfile = cmd[cmd.index("--force") - 1].replace("k.pub", "k-cert.pub")
                Path(certfile).write_text("ssh-ed25519-cert-v01@openssh.com AAAA_EVAC_CERT")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if cmd[0] == "ssh-keygen":
                return subprocess.CompletedProcess(cmd, 0, stdout="        Valid: from now to later\n", stderr="")
            raise AssertionError(f"Unexpected cmd: {cmd}")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=fake_run):
            code, body = self._invoke_post("/approve", token)
        self.assertEqual(code, 200)
        self.assertEqual(body, "approved")
        audit_text = Path(self.audit_file).read_text()
        self.assertIn("EVACUATE", audit_text)
        self.assertIn("SIGN", audit_text)

        # Case 2: Evacuation script returns 0 but fails to move off target-host-1 -> must fail closed (409)
        host_file.write_text("target-host-1\n")
        self.approver.handle_request(payload)
        token2 = next(iter(self.approver._pending.keys()))

        def stuck_run(cmd, *a, **kw):
            if cmd[0] == str(evac_script):
                return subprocess.CompletedProcess(cmd, 0, stdout="noop", stderr="")
            raise AssertionError("sign_cert must NOT be called when still on target hypervisor")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=stuck_run):
            code2, body2 = self._invoke_post("/approve", token2)
        self.assertEqual(code2, 409)
        self.assertIn("EVACUATE_FAIL", Path(self.audit_file).read_text())

    def test_airlock07_ansible_target_role_and_contrib_guard_structure(self):
        """AIRLOCK-07: Ansible target onboarding role and optional contrib hypervisor guard files exist and default to guard disabled."""
        defaults_yml = (REPO_ROOT / "ansible" / "roles" / "airlock_target" / "defaults" / "main.yml").read_text()
        tasks_yml = (REPO_ROOT / "ansible" / "roles" / "airlock_target" / "tasks" / "main.yml").read_text()
        handlers_yml = (REPO_ROOT / "ansible" / "roles" / "airlock_target" / "handlers" / "main.yml").read_text()

        self.assertIn("airlock_hypervisor_guard_enabled: false", defaults_yml)
        self.assertIn("AuthorizedPrincipalsFile {{ airlock_principals_dir }}/%u", tasks_yml)
        self.assertIn("ssh.socket", handlers_yml)

        for script_name in ("inject-host-identity.sh", "airlock-set-host", "airlock-evacuate"):
            p = REPO_ROOT / "contrib" / "proxmox-hypervisor-guard" / script_name
            self.assertTrue(p.is_file(), f"Missing {p}")
            self.assertTrue(os.access(p, os.X_OK), f"{p} is not executable")


    def test_airlock08_enroll_request_validation_and_approval_flow(self):
        """AIRLOCK-08a: Day-0 enroll validates hostname/private IP, escrows break-glass key, runs playbook, and updates allowlist."""
        # 1. Invalid hostname and non-private IPs must be rejected
        for bad_target, bad_ip in [
            ("bad host!", "10.6.31.1"),
            ("-leading-dash", "10.6.31.1"),
            ("transcribe", "8.8.8.8"),
            ("transcribe", "127.0.0.1"),
            ("transcribe", "not-an-ip"),
        ]:
            self.approver.handle_request(json.dumps({
                "action": "enroll",
                "req_id": SAMPLE_REQ_ID,
                "target": bad_target,
                "target_ip": bad_ip,
                "reason": "test bad enroll",
            }))
            self.assertEqual(len(self.approver._pending), 0)

        # 2. Configure temp files for USER_CA_PUBKEY_FILE, BIRTH_KEY_FILE, ONBOARD_PLAYBOOK, BREAK_GLASS_ESCROW_DIR, ALLOWLIST_FILE
        ca_pub = Path(self.tmpdir.name) / "user_ca.pub"
        ca_pub.write_text(SAMPLE_PUBKEY + "\n")
        birth_key = Path(self.tmpdir.name) / "birth_key"
        birth_key.write_text("PRIVATE_BIRTH_KEY\n")
        birth_pub = Path(self.tmpdir.name) / "birth_key.pub"
        birth_pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBirthKeyTest airlock-birth-key\n")
        playbook = Path(self.tmpdir.name) / "onboard-target.yml"
        playbook.write_text("---\n- hosts: airlock_targets\n")
        escrow_dir = Path(self.tmpdir.name) / "escrow"
        allowlist_file = Path(self.tmpdir.name) / "target-allowlist"

        self.approver.USER_CA_PUBKEY_FILE = str(ca_pub)
        self.approver.BIRTH_KEY_FILE = str(birth_key)
        self.approver.ONBOARD_PLAYBOOK = str(playbook)
        self.approver.BREAK_GLASS_ESCROW_DIR = str(escrow_dir)
        self.approver.ALLOWLIST_FILE = str(allowlist_file)

        # Confirm 'transcribe' is not yet allowlisted
        self.assertFalse(self.approver.is_target_allowlisted("transcribe"))

        self.approver.handle_request(json.dumps({
            "action": "enroll",
            "req_id": SAMPLE_REQ_ID,
            "target": "transcribe",
            "target_ip": "10.6.31.1",
            "reason": "Onboard new transcribe LXC 3101",
        }))
        self.assertEqual(len(self.approver._pending), 1)
        self.assertEqual(self.published[-1]["actions"][0]["label"], "Approve: Enroll & Lock")
        token = next(iter(self.approver._pending.keys()))

        captured_inventory = {}
        real_run = subprocess.run

        def fake_enroll_run(cmd, *a, **kw):
            if cmd[0] == "ssh-keygen":
                return real_run(cmd, *a, **kw)
            if cmd[0] == self.approver.ANSIBLE_PLAYBOOK_CMD:
                inv_path = cmd[cmd.index("-i") + 1]
                captured_inventory.update(json.loads(Path(inv_path).read_text()))
                return subprocess.CompletedProcess(cmd, 0, stdout="PLAY RECAP ok=8", stderr="")
            raise AssertionError(f"Unexpected subprocess cmd: {cmd}")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=fake_enroll_run):
            code, body = self._invoke_post("/approve", token)

        self.assertEqual(code, 200)
        self.assertEqual(body, "enrolled")

        # Verify break-glass private key was escrowed with 0600 permissions
        escrowed_priv = escrow_dir / "transcribe.id_ed25519"
        escrowed_pub = escrow_dir / "transcribe.id_ed25519.pub"
        self.assertTrue(escrowed_priv.is_file())
        self.assertTrue(escrowed_pub.is_file())
        self.assertEqual(escrowed_priv.stat().st_mode & 0o777, 0o600)

        # Verify inventory passed to ansible-playbook had birth key + break-glass pubkey + purge_birth_pubkey
        host_vars = captured_inventory["all"]["children"]["airlock_targets"]["hosts"]["transcribe"]
        self.assertEqual(host_vars["ansible_host"], "10.6.31.1")
        self.assertEqual(host_vars["ansible_ssh_private_key_file"], str(birth_key))
        self.assertTrue(host_vars["airlock_manage_authorized_keys"])
        self.assertEqual(host_vars["airlock_break_glass_pubkey"], escrowed_pub.read_text().strip())
        self.assertIn("airlock-birth-key", host_vars["airlock_purge_birth_pubkey"])

        # Verify allowlist updated in memory and on disk
        self.assertTrue(self.approver.is_target_allowlisted("transcribe"))
        self.assertIn("transcribe", allowlist_file.read_text().splitlines())
        self.assertIn("ENROLL", Path(self.audit_file).read_text())

    def test_airlock08_enroll_fails_closed_if_playbook_fails(self):
        """AIRLOCK-08b: If ansible-playbook fails during enrollment, target is NOT added to TARGET_ALLOWLIST."""
        ca_pub = Path(self.tmpdir.name) / "user_ca.pub"
        ca_pub.write_text(SAMPLE_PUBKEY + "\n")
        birth_key = Path(self.tmpdir.name) / "birth_key"
        birth_key.write_text("PRIVATE_BIRTH_KEY\n")
        playbook = Path(self.tmpdir.name) / "onboard-target.yml"
        playbook.write_text("---\n- hosts: airlock_targets\n")
        escrow_dir = Path(self.tmpdir.name) / "escrow"

        self.approver.USER_CA_PUBKEY_FILE = str(ca_pub)
        self.approver.BIRTH_KEY_FILE = str(birth_key)
        self.approver.ONBOARD_PLAYBOOK = str(playbook)
        self.approver.BREAK_GLASS_ESCROW_DIR = str(escrow_dir)
        self.approver.ALLOWLIST_FILE = ""

        self.approver.handle_request(json.dumps({
            "action": "enroll",
            "req_id": SAMPLE_REQ_ID,
            "target": "new-lxc",
            "target_ip": "10.6.31.9",
            "reason": "test failure",
        }))
        token = next(iter(self.approver._pending.keys()))
        real_run = subprocess.run

        def failing_playbook_run(cmd, *a, **kw):
            if cmd[0] == "ssh-keygen":
                return real_run(cmd, *a, **kw)
            if cmd[0] == self.approver.ANSIBLE_PLAYBOOK_CMD:
                raise subprocess.CalledProcessError(2, cmd, stderr="UNREACHABLE")
            raise AssertionError(f"Unexpected cmd: {cmd}")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=failing_playbook_run):
            code, _ = self._invoke_post("/approve", token)

        self.assertEqual(code, 500)
        self.assertFalse(self.approver.is_target_allowlisted("new-lxc"))
        self.assertIn("ENROLL_FAIL", Path(self.audit_file).read_text())

    def test_airlock08_airlock_cli_and_symlinks(self):
        """AIRLOCK-08c: airlock-enroll and airlock-* symlinks exist and are executable."""
        for script_name in ("airlock-enroll", "airlock-request", "airlock-approver.py", "ufw-rules.sh"):
            p = REPO_ROOT / "scripts" / script_name
            self.assertTrue(p.exists(), f"Missing {p}")
            self.assertTrue(os.access(p, os.X_OK), f"{p} is not executable")


    def test_airlock09_multi_approver_routing_principal_stamping_and_opa_silent_precheck(self):
        """AIRLOCK-09: Supports per-approver ntfy topics, approved-by-<approver>@<target> principal stamping, and silent_precheck OPA mode (zero permission oracle)."""
        self.approver.PER_APPROVER_TOPICS = True
        self.approver.STAMP_APPROVER_PRINCIPAL = True

        # 1. Request specifying approver='teletraan' routes to 'airlock-approvals-teletraan'
        req_payload = json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "30m",
            "reason": "restart container",
            "pubkey": SAMPLE_PUBKEY,
            "approver": "teletraan",
        })
        self.approver.handle_request(req_payload)
        self.assertEqual(len(self.approver._pending), 1)
        self.assertEqual(self.published[-1]["topic"], "airlock-approvals-teletraan")
        token = next(iter(self.approver._pending.keys()))

        captured_step_cmd = []

        def fake_sign_run(cmd, *a, **kw):
            if cmd[:3] == ["step", "ssh", "certificate"]:
                captured_step_cmd.extend(cmd)
                certfile = cmd[cmd.index("--force") - 1].replace("k.pub", "k-cert.pub")
                Path(certfile).write_text("ssh-ed25519-cert-v01@openssh.com AAAA_TELETRAAN_CERT")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if cmd[0] == "ssh-keygen":
                return subprocess.CompletedProcess(cmd, 0, stdout="        Valid: from now to later\n", stderr="")
            raise AssertionError(f"Unexpected cmd: {cmd}")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=fake_sign_run):
            code, body = self._invoke_post("/approve", token)

        self.assertEqual(code, 200)
        self.assertEqual(body, "approved")
        self.assertIn("approved-by-teletraan@target-host-1", captured_step_cmd)
        cert_msgs = [m for m in self.published if m["topic"] == self.approver.TOPIC_CERT]
        self.assertEqual(len(cert_msgs), 1)
        self.assertEqual(json.loads(cert_msgs[0]["message"])["approver"], "teletraan")
        self.assertIn("approver=teletraan", Path(self.audit_file).read_text())

        # 2. Enable PRECHECK_MODE = 'silent_precheck'; when OPA denies, approver is NOT paged and TOPIC_CERT receives NOTHING (zero permission oracle!)
        self.published.clear()
        self.approver.PRECHECK_MODE = "silent_precheck"
        self.approver.OPA_PRECHECK_URL = "http://127.0.0.1:8181/v1/data/airlock/allow"

        class FakeOpaResp:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass
            def read(self):
                return b'{"result": false}'

        with mock.patch.object(self.approver.urlrequest, "urlopen", return_value=FakeOpaResp()):
            self.approver.handle_request(json.dumps({
                "req_id": SAMPLE_REQ_ID,
                "target": "target-host-1",
                "duration": "30m",
                "reason": "unauthorized approver probe",
                "pubkey": SAMPLE_PUBKEY,
                "approver": "derpy",
            }))

        # Pending queue must be empty, derpy's channel was NOT paged, and TOPIC_CERT is silent
        self.assertEqual(len(self.approver._pending), 0)
        self.assertEqual([m for m in self.published if m["topic"] == "airlock-approvals-derpy"], [])
        self.assertEqual([m for m in self.published if m["topic"] == self.approver.TOPIC_CERT], [])
        self.assertIn("PRECHECK_DENIED", Path(self.audit_file).read_text())


    def test_airlock10_enroll_protects_existing_break_glass_and_rolls_back_on_failure(self):
        """AIRLOCK-10a (QA-01, QA-06, QA-09): Rejects re-enrolling an already-enrolled/escrowed target and rolls back staged key if playbook fails."""
        ca_pub = Path(self.tmpdir.name) / "user_ca.pub"
        ca_pub.write_text(SAMPLE_PUBKEY + "\n")
        birth_key = Path(self.tmpdir.name) / "birth_key"
        birth_key.write_text("PRIVATE_BIRTH_KEY\n")
        playbook = Path(self.tmpdir.name) / "onboard-target.yml"
        playbook.write_text("---\n- hosts: airlock_targets\n")
        escrow_dir = Path(self.tmpdir.name) / "escrow"
        escrow_dir.mkdir(parents=True, exist_ok=True)

        self.approver.USER_CA_PUBKEY_FILE = str(ca_pub)
        self.approver.BIRTH_KEY_FILE = str(birth_key)
        self.approver.ONBOARD_PLAYBOOK = str(playbook)
        self.approver.BREAK_GLASS_ESCROW_DIR = str(escrow_dir)
        self.approver.ALLOWLIST_FILE = ""

        # 1. Target already in TARGET_ALLOWLIST ('target-host-1') must be rejected at handle_request
        self.approver.handle_request(json.dumps({
            "action": "enroll",
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "target_ip": "10.6.31.1",
            "reason": "attempt re-enroll",
        }))
        self.assertEqual(len(self.approver._pending), 0)

        # 2. Target with pre-existing escrowed break-glass key must be rejected and key preserved
        existing_priv = escrow_dir / "existing-box.id_ed25519"
        existing_priv.write_text("PRECIOUS_EXISTING_BREAK_GLASS_KEY\n")
        self.approver.handle_request(json.dumps({
            "action": "enroll",
            "req_id": SAMPLE_REQ_ID,
            "target": "existing-box",
            "target_ip": "10.6.31.2",
            "reason": "attempt overwrite",
        }))
        self.assertEqual(len(self.approver._pending), 0)
        self.assertEqual(existing_priv.read_text(), "PRECIOUS_EXISTING_BREAK_GLASS_KEY\n")

        # 3. Duplicate pending enroll request for the same new target is deduplicated
        self.approver.handle_request(json.dumps({
            "action": "enroll",
            "req_id": SAMPLE_REQ_ID,
            "target": "fresh-box",
            "target_ip": "10.6.31.3",
            "reason": "first request",
        }))
        self.approver.handle_request(json.dumps({
            "action": "enroll",
            "req_id": "b1b2c3d4e5f60718",
            "target": "fresh-box",
            "target_ip": "10.6.31.3",
            "reason": "duplicate request",
        }))
        self.assertEqual(len(self.approver._pending), 1)
        token = next(iter(self.approver._pending.keys()))

        # 4. If playbook fails, staged escrow key for 'fresh-box' is rolled back so retry can succeed
        real_run = subprocess.run

        def fail_once(cmd, *a, **kw):
            if cmd[0] == "ssh-keygen":
                return real_run(cmd, *a, **kw)
            if cmd[0] == self.approver.ANSIBLE_PLAYBOOK_CMD:
                raise subprocess.TimeoutExpired(cmd, 120)
            raise AssertionError(f"Unexpected cmd: {cmd}")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=fail_once):
            code, _ = self._invoke_post("/approve", token)

        self.assertEqual(code, 500)
        self.assertFalse((escrow_dir / "fresh-box.id_ed25519").exists())
        self.assertIn("ENROLL_FAIL", Path(self.audit_file).read_text())

    def test_airlock10_enroll_ignores_untrusted_rec_overrides(self):
        """AIRLOCK-10b (QA-02): enroll_target ignores untrusted extra_authorized_keys or sshd_dropin_path in rec."""
        ca_pub = Path(self.tmpdir.name) / "user_ca.pub"
        ca_pub.write_text(SAMPLE_PUBKEY + "\n")
        birth_key = Path(self.tmpdir.name) / "birth_key"
        birth_key.write_text("PRIVATE_BIRTH_KEY\n")
        playbook = Path(self.tmpdir.name) / "onboard-target.yml"
        playbook.write_text("---\n- hosts: airlock_targets\n")
        escrow_dir = Path(self.tmpdir.name) / "escrow"

        self.approver.USER_CA_PUBKEY_FILE = str(ca_pub)
        self.approver.BIRTH_KEY_FILE = str(birth_key)
        self.approver.ONBOARD_PLAYBOOK = str(playbook)
        self.approver.BREAK_GLASS_ESCROW_DIR = str(escrow_dir)
        self.approver.ALLOWLIST_FILE = ""

        captured_inv = {}
        real_run = subprocess.run

        def capture_playbook(cmd, *a, **kw):
            if cmd[0] == "ssh-keygen":
                return real_run(cmd, *a, **kw)
            if cmd[0] == self.approver.ANSIBLE_PLAYBOOK_CMD:
                inv_path = cmd[cmd.index("-i") + 1]
                captured_inv.update(json.loads(Path(inv_path).read_text()))
                return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")
            raise AssertionError(f"Unexpected cmd: {cmd}")

        with mock.patch.object(self.approver.subprocess, "run", side_effect=capture_playbook):
            self.approver.enroll_target({
                "target": "safe-box",
                "target_ip": "10.6.31.4",
                "extra_authorized_keys": ["ssh-ed25519 AAAA_ATTACKER"],
                "sshd_dropin_path": "/etc/cron.d/pwn",
                "principal_uid": 0,
            })

        hvars = captured_inv["all"]["children"]["airlock_targets"]["hosts"]["safe-box"]
        self.assertEqual(hvars["airlock_extra_authorized_keys"], [])
        self.assertNotIn("airlock_sshd_dropin_path", hvars)
        self.assertNotIn("airlock_principal_uid", hvars)
        self.assertIn("UserKnownHostsFile=", hvars["ansible_ssh_common_args"])

    def test_airlock10_reap_expired_audits_and_evacuate_script_hardened(self):
        """AIRLOCK-10c (QA-03, QA-04, QA-11, QA-15): reap_expired writes EXPIRE to audit log; airlock-evacuate & airlock_server are hardened."""
        self.approver.handle_request(json.dumps({
            "req_id": SAMPLE_REQ_ID,
            "target": "target-host-1",
            "duration": "30m",
            "reason": "test expire audit",
            "pubkey": SAMPLE_PUBKEY,
        }))
        token = next(iter(self.approver._pending.keys()))
        self.approver._pending[token]["expiry"] = time.time() - 10
        self.approver.reap_expired()
        self.assertEqual(len(self.approver._pending), 0)
        self.assertIn("EXPIRE", Path(self.audit_file).read_text())

        evac_txt = (REPO_ROOT / "contrib" / "proxmox-hypervisor-guard" / "airlock-evacuate").read_text()
        self.assertIn('SAFE_HOST="${TARGET_HOST//[-.]/_}"', evac_txt)
        self.assertIn("--config -", evac_txt)

        server_tasks = (REPO_ROOT / "ansible" / "roles" / "airlock_server" / "tasks" / "main.yml").read_text()
        self.assertIn("/etc/airlock/db", server_tasks)
        self.assertIn("--provisioner-password-file=/etc/airlock/secrets/provisioner_password", server_tasks)



    def test_1password_escrow_helper_script(self):
        """airlock-escrow-1password pipes JSON item payload to `op item create -` without leaking key in argv."""
        script = REPO_ROOT / "scripts" / "airlock-escrow-1password"
        mock_op = Path(self.tmpdir.name) / "mock-op"
        captured_stdin = Path(self.tmpdir.name) / "op_stdin.json"
        captured_args = Path(self.tmpdir.name) / "op_args.txt"
        token_file = Path(self.tmpdir.name) / "op.token"
        token_file.write_text("ops_dummy_service_account_token\n")

        mock_op.write_text(
            f"""#!/usr/bin/env python3
import os, sys
from pathlib import Path
assert os.environ.get("OP_SERVICE_ACCOUNT_TOKEN") == "ops_dummy_service_account_token"
Path({str(captured_args)!r}).write_text(" ".join(sys.argv[1:]))
Path({str(captured_stdin)!r}).write_text(sys.stdin.read())
print('{{"id": "op_item_12345"}}')
"""
        )
        mock_op.chmod(0o755)

        fake_priv = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----\n"
        env = os.environ.copy()
        env["AIRLOCK_OP_BIN"] = str(mock_op)
        env["AIRLOCK_OP_TOKEN_FILE"] = str(token_file)
        env["AIRLOCK_OP_VAULT"] = "Homelab Break-Glass"

        res = subprocess.run(
            [str(script), "transcribe", "10.6.31.1"],
            input=fake_priv,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertIn("id=op_item_12345", res.stdout)

        # Verify private key was NOT passed in CLI args, only via JSON stdin
        args_str = captured_args.read_text()
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", args_str)
        self.assertIn("item create --vault Homelab Break-Glass --format json -", args_str)

        payload = json.loads(captured_stdin.read_text())
        self.assertEqual(payload["title"], "Airlock Break-Glass — transcribe (10.6.31.1)")
        fields = {f["id"]: f["value"] for f in payload["fields"]}
        self.assertEqual(fields["ssh_private_key"], fake_priv)


if __name__ == "__main__":
    unittest.main()
