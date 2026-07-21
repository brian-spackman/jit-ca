# Homelab JIT-CA — replication guide

A complete, reproducible build of just-in-time SSH elevation for an AI agent (or any low-trust automation), using `step-ca`, `ntfy`, and OpenSSH certificates. Written to be read by a careful human *or* handed to a capable coding agent as a build spec.

Read [README.md](./README.md) first for the "what" and "why". This document is the "how" — a narrative build with real gotchas and the reasoning behind each step. If you'd rather have a single, leaner, tool-agnostic document instead, see [JIT-CA-SPEC.md](./JIT-CA-SPEC.md).

---

## 0. Conventions

This guide uses placeholders. Substitute your own values; nothing here is secret except where flagged. (The reference deployment this is distilled from uses different real names/IPs.)

| Placeholder | Meaning | Example |
|---|---|---|
| `CA_HOST` | The dedicated CA / approver box | `10.0.0.10` |
| `AGENT_HOST` | The box your AI agent runs on | `10.0.0.5` |
| `TARGET_HOST` | A machine the agent needs to reach | `10.0.0.20` |
| `LAN_CIDR` | Your trusted LAN subnet | `10.0.0.0/24` |
| `VPN_CIDR` | Your VPN subnet (optional, for off-LAN approval) | `10.5.0.0/24` |
| `NTFY_FQDN` | Public name for ntfy (optional, for off-LAN approval) | `ntfy.example.net` |
| `PRINCIPAL` | The SSH cert principal == service username on targets | `agent` |
| `PROVISIONER` | step-ca SSH provisioner name | `jit-ssh` |
| `STEPPATH` | step-ca config/state dir | `/etc/jit-ca` |

Reference versions (pin these — `step-ca`'s SSH CA flags have drifted across releases): **step-cli 0.30.6, step-ca 0.30.2, ntfy 2.24.0**, OpenSSH 9.x, Debian 12/13.

This guide is descriptive, not a script drop — it names two pieces, **`jit-ca-approver.py`** (the approval daemon) and **`jit-request`** (the agent CLI), and explains exactly what each one does and how to wire it, in enough detail to implement from scratch (Sections 5–7 are the concrete build steps). Sanitized reference implementations of both scripts (plus the systemd unit and the ufw rules) are in the [`scripts/`](./scripts/) directory — read the narrative here first, then use those as a starting point rather than building from scratch.

---

## 1. Trust model

Three roles, deliberately separated so no single compromise grants target access:

```
 AGENT_HOST                    CA_HOST                         your phone
 ─ holds an SSH keypair        ─ runs step-ca (SSH CA)         ─ ntfy app
 ─ can PUBLISH requests        ─ runs the approver daemon      ─ holds approve/deny
 ─ can READ signed certs       ─ holds ALL signing keys          authority (the tap)
 ─ CANNOT approve or sign      ─ holds NO credential to agent
```

The separation is enforced in three places:

1. **No key material on targets.** Targets trust the CA via `TrustedUserCAKeys`. They have no `authorized_keys` entry for the agent. A valid cert is the *only* way in.
2. **The CA holds nothing pointing back at the agent.** The signed cert is delivered to the agent over the *notification channel* (it's a signed public key, not a secret), so the CA never needs an outbound credential or SSH path to the agent. Authority flows one way.
3. **The notification-channel ACLs split request / approve / deliver.** (Section 4.) The agent account can *write* requests and *read* certs but **cannot read the approvals topic**, so it can never see the one-time approval tokens. It can ask; it cannot approve.

Result: an attacker who fully owns `AGENT_HOST` can issue requests, but cannot mint a cert without a physical tap on your phone, and cannot reach a target without a cert.

---

## 2. Topology & prerequisites

- A **dedicated** `CA_HOST` (a 1 vCPU / 512 MB / 4 GB LXC or VM is plenty). It should be a box the agent has **no standing path into** in steady state. Minimal Debian is ideal.
- `AGENT_HOST` with Python 3 and OpenSSH client.
- One or more `TARGET_HOST`s running OpenSSH server.
- The `ntfy` Android/iOS app on your phone.
- A trusted LAN. (Off-LAN approval needs a reverse proxy + VPN — Section 4.4.)

---

## 3. The SSH Certificate Authority (`step-ca`)

On `CA_HOST`:

```bash
# Install step-cli + step-ca (pin versions). Smallstep publishes .deb packages.
# Then create a dedicated, unprivileged service user that owns the CA state.
sudo useradd --system --home-dir /etc/jit-ca --shell /usr/sbin/nologin step
export STEPPATH=/etc/jit-ca
```

Initialize the CA. We only need the **SSH** CA features (not X.509 issuance), but `step ca init` sets up the root/intermediate scaffold and the SSH user/host keys in one go:

```bash
sudo -u step env STEPPATH=$STEPPATH step ca init \
  --ssh \
  --name "homelab-jit-ca" \
  --dns "localhost" \
  --address "127.0.0.1:9000" \
  --provisioner "jit-ssh"
```

> **Provisioner name:** the `--provisioner` value becomes the provisioner name in `config/ca.json` and must match `PROVISIONER` in `jit-ca-approver.py`. The approver script (and this guide) use `jit-ssh` throughout; the `step ca init` command above already passes that value. If you use a different name, update `PROVISIONER` in the script to match.

This writes under `$STEPPATH`:

- `config/ca.json` — the CA config.
- `certs/ssh_user_ca_key.pub` — **the public key you distribute to every target.** Not secret.
- `certs/ssh_host_ca_key.pub` — host CA pubkey (optional host-cert hardening, Section 9).
- `secrets/ssh_user_ca_key`, `secrets/ssh_host_ca_key` — the **signing keys** (secret).
- `secrets/root_ca_key`, `secrets/intermediate_ca_key` — X.509 keys (secret; unused by the SSH path but part of the trust root — back them up).
- `secrets/password`, `secrets/provisioner_password` — the passphrases that decrypt the above.

Enable SSH CA on the provisioner. In `config/ca.json`, the SSH provisioner block should carry `"claims": { "enableSSHCA": true }`, and the top-level `"ssh"` block should point `userKey` / `hostKey` at the secrets above:

```jsonc
"ssh": {
  "hostKey": "/etc/jit-ca/secrets/ssh_host_ca_key",
  "userKey": "/etc/jit-ca/secrets/ssh_user_ca_key"
},
"authority": {
  "provisioners": [
    { "type": "JWK", "name": "jit-ssh", "key": { /* … */ },
      "encryptedKey": "…", "claims": { "enableSSHCA": true } }
  ]
}
```

Run it under systemd as the `step` user, with the CA password supplied from a file (so it boots unattended):

```ini
# /etc/systemd/system/step-ca.service
[Unit]
Description=step-ca SSH Certificate Authority
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=step
Group=step
Environment=STEPPATH=/etc/jit-ca
ExecStart=/usr/bin/step-ca /etc/jit-ca/config/ca.json --password-file /etc/jit-ca/secrets/password
ExecReload=/bin/kill --signal HUP $MAINPID
Restart=on-failure
RestartSec=5
# hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/jit-ca/db
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now step-ca
curl -sk https://localhost:9000/health     # -> {"status":"ok"}
```

> **Unattended-boot tradeoff:** supplying `--password-file` means the CA password lives in plaintext on `CA_HOST` so the service can start without a human. That's the pragmatic choice for a home lab. If you want stronger at-rest protection, drop the password file and unlock the CA manually after boot (or via a KMS) — at the cost of the CA not surviving a reboot on its own.

**Signing an SSH cert** (this is what the approver calls — verify it works manually first):

```bash
sudo -u step env STEPPATH=/etc/jit-ca step ssh certificate \
  --provisioner jit-ssh \
  --principal agent \
  --not-after 1h \
  --sign --force \
  agent /path/to/agent_key.pub
# inspect: ssh-keygen -L -f agent_key-cert.pub  → confirm  Principals: agent  and the validity window
```

> **Scope your principals.** Always pass `--principal`. A cert with an *empty* principals list is valid for **any** username on a trusting host. Verify with `ssh-keygen -L` that `Principals:` lists exactly your intended principal, and confirm other users (e.g. `root`) are denied (Section 11).

---

## 4. The notification / transport channel (`ntfy`)

`ntfy` does triple duty: it carries the **request** (agent → CA), the **approval prompt with buttons** (CA → phone), and the **signed cert** (CA → agent). Self-host it on `CA_HOST`.

### 4.1 Install & configure

```yaml
# /etc/ntfy/server.yml
base-url: "https://ntfy.example.net"   # set even on LAN if you front it with TLS (Section 4.4)
listen-http: "10.0.0.10:8080"          # bind the LAN IP, not 0.0.0.0; never expose to WAN
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"        # critical: topics are private by default
cache-file: "/var/lib/ntfy/cache.db"
cache-duration: "12h"                  # lets the agent poll for its cert reliably
behind-proxy: true                     # if fronted by a reverse proxy
enable-signup: false
enable-login: true
```

```bash
sudo systemctl enable --now ntfy
```

### 4.2 Topics & access control (the load-bearing part)

Three topics, three least-privilege accounts. This ACL split is what makes "the agent can ask but cannot approve" *structurally* true rather than merely conventional:

```bash
# create accounts
sudo ntfy user add approver        # the daemon on CA_HOST
sudo ntfy user add agent           # the agent on AGENT_HOST
sudo ntfy user add phone           # you

# topic ACLs
#   jit-requests : agent → CA       (the ask)
#   jit-approvals: CA → phone       (the actionable notification + token)
#   jit-certs    : CA → agent       (the signed cert)

sudo ntfy access approver jit-requests  read-only
sudo ntfy access approver jit-approvals write-only
sudo ntfy access approver jit-certs     write-only

sudo ntfy access agent    jit-requests  write-only
sudo ntfy access agent    jit-certs     read-only
#   NOTE: agent gets NO access to jit-approvals — it can never see approval tokens.

sudo ntfy access phone    jit-approvals read-write
sudo ntfy access phone    jit-requests  read-write
```

> **OFI: phone access is read-write, not read-only.** The `phone` account is granted read-write on both topics above mainly because it wasn't obvious how to get a read-only subscription working in the ntfy mobile app for the approvals topic. Read-write is broader than the phone strictly needs (it never needs to *publish* to `jit-requests`, for instance) — a reasonable simplification for a homelab, but worth tightening if your threat model calls for it.

Generate access tokens for the `approver` and `agent` accounts (`ntfy token add <user>`). The approver reads its token from a secrets file on `CA_HOST`; the agent stores its token at `~/.config/jit-ca/ntfy-agent-token` on `AGENT_HOST`.

### 4.3 Connect your phone

Install the ntfy app, point it at your server (`https://NTFY_FQDN`, or the LAN URL), log in as the `phone` user, and subscribe to `jit-approvals`. Send yourself a test message to confirm delivery before relying on it.

### 4.4 Off-LAN approval (optional)

To approve while away from home, the phone must reach two things: the ntfy server (to receive the prompt) **and** the approver's webhook (to send the tap — Section 5). The clean way is to front ntfy with a reverse proxy (TLS) at `NTFY_FQDN`, reachable over your VPN, and to route the approve action through that same proxy rather than a direct hit to the webhook port. If you only ever approve on the LAN, you can skip this — but see the **ufw gotcha** in Section 8, because a half-configured firewall makes off-LAN *look* like the problem when it isn't.

---

## 5. The approver daemon

`jit-ca-approver.py` runs on `CA_HOST` (as the `step` user) and does two jobs:

**Job 1 — subscribe to `jit-requests`.** For each request `{req_id, target, duration, reason, pubkey}` it:

- validates `target` against a `TARGET_ALLOWLIST` and `duration` against a hard cap (e.g. 8h);
- stashes the full request server-side under a freshly generated **single-use, ~10-minute token**;
- publishes an **actionable notification** to `jit-approvals` titled e.g. *"Agent wants SSH access — TARGET for DURATION: REASON"*, carrying two HTTP-action buttons, **Approve** and **Deny**, each POSTing the token to the approver's own webhook.

> **OFI: externalize the allowlist.** `TARGET_ALLOWLIST` is a hardcoded Python set in the reference script. That's fine for a handful of targets, but it means every fleet change is a code edit and a restart. A cleaner design is a separate config file (YAML works well) that the script reads at startup — easier to manage as the fleet grows, and it decouples allowlist changes from touching code at all.

**Job 2 — serve a tiny webhook** (`/approve`, `/deny`) bound to the LAN IP. On a valid **Approve**:

- it looks up the stashed request by token, marks the token consumed (single-use — replay is rejected);
- calls `step ssh certificate --provisioner PROVISIONER --principal PRINCIPAL --not-after <duration> --sign --force PRINCIPAL <agent_pubkey>`;
- publishes the resulting **cert** to `jit-certs`;
- appends a line to an audit log (`SIGN` / `DENY` / `SIGN_FAIL` with timestamp, target, duration, reason, req_id, validity window) **and** to the system journal, so both a durable audit trail and quick `journalctl` visibility exist for every outcome.

On **Deny**, do the mirror-image of Approve, deliberately: burn the token, write the audit line, log it — but do **not** publish anything distinguishing to the topic the agent can read (`jit-certs`). If you want the agent's CLI to exit quickly on a deny instead of running out the full timeout, publish a *generic* close-out message there (`{"req_id": ..., "cert": null}`) — the same message shape a future `SIGN_FAIL` or other terminal-without-a-cert state would use. The agent's client only ever learns "no cert is coming," never *why* — deny, error, and timeout are indistinguishable from its side. That's a deliberate security property, not an oversight: if the agent is ever the compromised party, it should never learn whether a human is actively watching and rejecting it versus simply not having looked yet.

> **Log Deny with the same completeness as Approve.** It's tempting to treat Deny as the trivial mirror image of Approve and give it lighter logging — but a Deny path that only writes the audit file and skips the journal means a live deny tap produces zero visible signal in `journalctl`. That looks exactly like "the phone's tap isn't reaching the daemon," a plausible and much scarier-looking client-side bug, when the real fault is a missing log call on one branch of the server. Give Approve and Deny identical logging coverage from the start, and test Deny explicitly and early — see the Known Gotchas section (Section 14) for why untested paths are the ones that bite.

Key design choices baked into the daemon:

- **Cert over ntfy, not scp.** The cert is a signed public key, so it can travel over the message bus. This is *why* the CA needs no credential pointing at the agent.
- **The agent never sees the token.** The token lives only in the notification (which the agent account can't read) and the approver's memory. The agent can spam `jit-requests`; it cannot manufacture an approval.
- **Single-use + short TTL tokens.** An un-tapped request simply expires; an approval can't be replayed.
- **Deny and timeout look identical to the agent.** See above — this is load-bearing for the "the agent cannot learn whether it's being watched" property, not just a UX nicety.

systemd unit (note the dependency ordering and the `ReadOnlyPaths` restriction on the CA dir). The inline block below is abbreviated for readability — `scripts/jit-ca-approver.service` in this repo is the canonical version with full hardening directives; prefer it:

```ini
# /etc/systemd/system/jit-ca-approver.service
[Unit]
Description=jit-ca approver — tap-to-sign SSH JIT approval daemon
After=network-online.target ntfy.service step-ca.service
Requires=ntfy.service step-ca.service

[Service]
Type=simple
User=step
Group=step
ExecStart=/usr/bin/python3 /usr/local/bin/jit-ca-approver
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/jit-ca
ReadOnlyPaths=/etc/jit-ca

[Install]
WantedBy=multi-user.target
```

---

## 6. The agent CLI

`jit-request` runs on `AGENT_HOST`. Usage:

```bash
jit-request <target> <duration> "<reason>"
# e.g.
jit-request target-host 1h "upgrade the app container to v2.0"
```

What it does:

1. Ensures an agent keypair exists at `~/.ssh/jit-ca/agent_key` (generates an ed25519 key on first run).
2. Publishes `{req_id, target, duration, reason, pubkey}` to `jit-requests` using the agent's ntfy token, then **blocks**, printing *"waiting for approval — tap Approve on your phone"*.
3. Polls `jit-certs` (with a short lookback window — ntfy's 12h cache makes this reliable), filtering by its own `req_id` so a stale cert from a prior request is ignored.
4. On match, writes the cert to `~/.ssh/jit-ca/agent_key-cert.pub` and prints the validity window. Times out after ~5 minutes if no approval arrives.

Wire it into the agent's `~/.ssh/config` so plain `ssh target-host` uses the cert and fails cleanly when there's no valid one:

```sshconfig
Host target-host
  HostName 10.0.0.20
  User agent
  IdentityFile ~/.ssh/jit-ca/agent_key
  CertificateFile ~/.ssh/jit-ca/agent_key-cert.pub
  IdentitiesOnly yes
```

With no current cert, `ssh target-host` is rejected (`Permission denied (publickey)`) — that's default-deny working, not a bug.

---

## 7. Onboarding a target host

One-time per machine. **Additive and reversible** — do it over an existing admin session; it does not disturb current access.

1. **Create the service user** (the agent's identity on this box). No password, no `authorized_keys`, only the groups it genuinely needs:

   ```bash
   sudo useradd -m -s /bin/bash agent
   sudo passwd -l agent                       # lock password: cert-only, no password auth
   sudo usermod -aG sudo agent                # only if the agent needs root here
   sudo usermod -aG docker agent              # only on a Docker host
   echo 'agent ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/agent
   sudo chmod 0440 /etc/sudoers.d/agent && sudo visudo -c
   ```

2. **Trust the CA.** Copy the **user** CA public key (`certs/ssh_user_ca_key.pub` from `CA_HOST`) onto the target and point sshd at it:

   ```bash
   sudo install -m 644 -o root -g root ssh_user_ca_key.pub /etc/ssh/trusted_user_ca_keys
   echo 'TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys' \
     | sudo tee /etc/ssh/sshd_config.d/10-jit-ca.conf
   sudo sshd -t && sudo systemctl reload ssh   # validate THEN reload; keep your session open
   ```

   > **Socket-activated sshd gotcha (Debian 13+).** On distros where `ssh.socket` triggers `ssh.service` per-connection, `reload`/`restart` on the service can report failure or even knock out the listener, because there's no long-running instance to signal — yet the config is already live for the *next* connection regardless, since it's read fresh each time. Check `systemctl status ssh.socket` first; if it's socket-activated, skip the reload entirely and just reconnect — don't restart anything, and always keep a fallback session open before touching sshd config either way.

3. **Allowlist the target** in the approver's `TARGET_ALLOWLIST` on `CA_HOST` and restart `jit-ca-approver`.

4. **Add the `Host` block** to the agent's `~/.ssh/config` (Section 6).

That's it — targets need **no** ntfy, no webhook, no extra firewall rules (only `CA_HOST` runs those). A target only needs sshd trusting the CA.

### Verify

```bash
jit-request target-host 30m "onboarding test"     # tap Approve on your phone
ssh-keygen -L -f ~/.ssh/jit-ca/agent_key-cert.pub  # Principals: agent ; ~30m window
ssh target-host 'id'                               # logs in as agent
# wait out the TTL → ssh target-host now fails: cert is the only path, and it expired
```

---

## 8. Firewall (ufw) — and the gotcha that will bite you

On `CA_HOST`, default-deny inbound and allow exactly three things:

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp                                          # admin SSH
sudo ufw allow from 10.0.0.0/24 to any port 8080 proto tcp     # ntfy   (LAN only)
sudo ufw allow from 10.0.0.0/24 to any port 8081 proto tcp     # approver webhook (LAN)
sudo ufw allow from 10.5.0.0/24 to any port 8081 proto tcp     # approver webhook (VPN — add if approving off-LAN)
sudo ufw --force enable
```

> **Reference script:** `scripts/ufw-rules.sh` in this repo captures these rules as a runnable, idempotent shell script — prefer it over the inline commands above, especially after a rebuild.

> **Watch for this:** if you enable ufw and allow the ntfy port (8080) but **forget the approver webhook port (8081)**, everything *looks* fine — the request goes through, the phone notification arrives — but every **Approve** tap is silently dropped at the firewall, because the tap POSTs to 8081 while the notification rode in on 8080. There's no error; the request just times out. **If "Approve does nothing", check the webhook port's ufw rule first.** (Confirm the rule with `sudo ufw status`, and watch for blocked packets with ufw logging on.) See also the Known Gotchas section (Section 14).

> **Off-LAN note:** a `from LAN_CIDR` rule won't match a VPN client whose packets carry a non-LAN source. If you approve over a VPN, either widen the rule to the VPN subnet or — better — route the approve action through the TLS reverse proxy (Section 4.4) instead of a direct hit to 8081.

Targets just need their normal SSH port open. `AGENT_HOST` needs no inbound rules for this system at all (it only makes outbound calls).

---

## 9. Backup & recovery

The CA's signing keys are the crown jewels: lose them and you must re-distribute a new CA pubkey to every target; leak them and someone can mint certs for your fleet.

- **Back up** the entire `$STEPPATH` tree (`config/`, `certs/`, `secrets/`, `db/`). The `secrets/` dir holds the *encrypted* signing keys **and** the password files that decrypt them — so a tarball of the whole tree is a complete restore artifact, but its encryption-at-rest is effectively void (passwords travel with keys). Treat the archive itself as secret.
- **Store it offline** — a password-manager attachment or encrypted USB — **not** on `AGENT_HOST` (the one box this design works to keep away from the CA).
- **Restore** onto a fresh box: install the same step versions, recreate the `step` user, `tar -C /etc -xzf <archive>`, fix ownership, reinstall the systemd unit, start it, hit `/health`. Because the CA pubkey is unchanged, every target still trusts it — no re-distribution needed.
- **Optional hardening:** issue **host** certificates to targets from the same CA so the agent can verify it's connecting to the genuine host (not load-bearing for the threat model, but nice). Pin `--principal` source-address restrictions on user certs if you want to bound where a cert can be used from.

---

## 10. Break-glass recovery — a human-held fallback per target

The system as built so far removes every *standing agent* credential — but that raises an obvious question: what happens if `CA_HOST` itself, or `ntfy`, is down? Without a fallback, a CA outage would lock you out of your own fleet along with the agent.

The fix: **a break-glass keypair per target, generated and held entirely by you, outside the agent's reach.**

- Generate the keypair yourself — a password manager with SSH key generation (1Password, Bitwarden) works well, or any offline `ssh-keygen` you control. The private key **never** touches `AGENT_HOST` or any agent-writable storage.
- Share only the **public** half with the agent, so it can install it — over whatever one-way channel you use to drop secrets to the agent (for example, a dedicated ntfy topic with the same `jit-certs`-style read-only ACL for the agent account).
- The agent installs that public key into the target's `authorized_keys`, **replacing** any standing key left over from the target's initial build — never leave both in place at once.
- Hand over the matching private key only if the tap-to-sign path itself breaks. This should be rare and deliberate, not a routine credential you keep on hand.

Net effect: **no machine in the fleet retains a private key that lets the agent bypass the tap-to-sign gate**, while you retain a recovery path independent of the CA's own uptime. Roll this out per target only *after* verifying the cert path works end-to-end on that target — the break-glass key should be a strictly-worse fallback, never the first thing you reach for.

---

## 11. Threat model & limits

**What it defends against:** a compromised, prompt-injectable, or simply buggy agent gaining *standing* access to your fleet. The agent has no target credentials; it cannot self-elevate; every elevation requires your physical tap; access auto-expires; everything is logged.

**What it does NOT do:**

- It is not a hardened, internet-facing PKI. It assumes a **trusted LAN** and a permissive home posture (e.g. plaintext password file for unattended CA boot; LAN-only plaintext webhook with the single-use token as the only secret).
- It does not protect a target *after* a legitimate cert is issued — within the cert's TTL and principal scope, the agent has exactly the access you approved (so scope principals and TTLs conservatively, and only grant `sudo`/`docker` where needed).
- The phone tap is the irreducible gate. Protect the phone and the `phone` ntfy account accordingly (the app's own PIN/biometric lock is worth enabling).

---

## 12. Operations & troubleshooting

- **"Approve does nothing."** In order: (1) is the webhook port allowed in ufw? (Section 8.) (2) `systemctl status jit-ca-approver` and its journal — a `publish failed` line points at an ntfy token/ACL problem; an `invalid/expired/used token` line means the prompt aged out (>token TTL) — just re-request. (3) Off-LAN? See Section 4.4.
- **"Cert never reaches the agent."** Poll `jit-certs` with the agent token; if the cert is there, `jit-request` was killed before it could write it; if not, check the approver's `SIGN_FAIL` audit lines.
- **Confirm principal scoping.** `ssh-keygen -L -f <cert>` must show `Principals: <your principal>`. Confirm a *different* user is denied on a target with that cert (a quick `ssh otheruser@target` should fail) — this catches an accidental empty-principal "valid for all users" cert.
- **Audit.** Everything funnels through one chokepoint, so the approver's audit log plus each target's sshd logs (which record the cert serial on login) give you a full who/what/when/why.
- **Test Deny, not just Approve.** It's the path most likely to sit unexercised — see the callout in Section 5. Fire a request, deny it deliberately, and confirm you see the signal you expect *before* you need Deny to matter for real.

---

## 13. Known limitations & v2 scope

What a genuinely working v1 still doesn't do — not a wishlist, a real gap list:

- **Onboarding is fully manual.** Every target in Section 7 is a by-hand walkthrough, repeated per box. It should be a script or an Ansible role; today it isn't.
- **No host certs.** The agent trusts whatever's listening at a target's configured IP; it has no cryptographic proof it's talking to the real target. Section 9's "optional hardening" closes this but isn't wired up by default.
- **No source-address pinning.** A cert works from anywhere on the trusted network the agent key can reach, not just from the actual agent host.
- **Off-LAN approval requires extra infrastructure** (Section 4.4) that most builds of this won't have set up, so approving away from home is a second-class path, not the default.
- **Cert expiry is silent.** No proactive notice when access lapses — you find out via the next failed SSH attempt.
- **The break-glass rollout (Section 10) is itself manual**, done target-by-target as each one gets built out, rather than a step baked into onboarding from day one.

---

## 14. Known Gotchas

Forward-looking warnings, not a changelog — things to watch for while you build this, regardless of whether you ever actually hit them:

- **Forgetting the approver webhook port in the firewall.** If you allow the ntfy port (8080) but forget the approve/deny webhook port (8081), everything *looks* fine — the request goes through and the phone notification arrives — but every **Approve** tap is silently dropped at the firewall, because the tap POSTs to 8081 while the notification rode in on 8080. There's no error; the request just times out. If "Approve does nothing", check the webhook port's ufw rule first (Section 8).
- **A firewall rule scoped to the LAN subnet won't match VPN clients.** If you approve from off-LAN, either widen the webhook rule to the VPN subnet or route the approve action through a TLS reverse proxy (Section 4.4) instead of a direct hit to the webhook port.
- **Give Deny the same logging completeness as Approve.** It's tempting to treat Deny as a lightweight mirror of Approve. If Deny only writes the audit file and skips the journal, a live deny tap produces zero visible signal in `journalctl` — which looks exactly like the phone's tap not reaching the daemon at all, a much scarier and harder-to-diagnose failure than "logging is incomplete on one branch." Build Approve and Deny with identical logging from day one.
- **Untested control paths are the ones that bite.** It's easy to build and repeatedly exercise Approve during development while Deny goes completely unexercised until someone needs it for real. Test Deny explicitly and early — don't assume a control path works just because a similar one does.
- **Socket-activated sshd (Debian 13+).** On distros where `ssh.socket` triggers `ssh.service` per-connection, `reload`/`restart` on the service can report failure or even knock out the listener, because there's no long-running instance to signal — yet the config is already live for the *next* connection regardless, since it's read fresh each time. Check `systemctl status ssh.socket` first; if it's socket-activated, skip the reload entirely and just reconnect. Don't restart anything, and always keep a fallback session open before touching sshd config either way (Section 7).

---

_Built and proven on a real home lab: `step-ca` SSH CA + self-hosted `ntfy` + a Python approver daemon, with a Docker host onboarded as the first live target. The pattern generalizes to any low-trust automation that occasionally needs real, scoped, auditable access to machines you care about._
