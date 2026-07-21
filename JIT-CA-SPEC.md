# JIT-CA: Just-in-time SSH access for an AI agent

A self-hosted pattern that lets an AI agent (or any semi-autonomous automation) reach other machines on a network **without ever holding a standing credential to them**. Access is granted per-task, expires on its own, and requires an explicit human approval — a tap on a phone — every single time. This document specifies the concept, the experience it produces, and enough implementation detail for a competent engineer or coding agent to build a working instance from scratch.

This is the single-file, tool-agnostic version of the build. For the narrative walkthrough with real-world gotchas and worked examples, see [README.md](./README.md) (the "what and why") and [REPLICATION-GUIDE.md](./REPLICATION-GUIDE.md) (the "how," in more depth than this document goes into). Sanitized reference scripts (approval daemon, systemd unit, agent CLI, ufw rules) are in the [`scripts/`](./scripts/) directory — use them as a starting point once you've read through the build instructions here.

---

## 1. The problem this solves

An AI agent that operates autonomously on one machine will, sooner or later, need to act on *other* machines: restart a service, apply an upgrade, inspect a log, push a config change. There are two common ways to handle this, and both are unsatisfying:

1. **Standing keys.** Give the agent SSH keys to everything it might need. This makes the agent itself the highest-value target in the environment — anything that compromises the agent (a prompt injection, a bug, a supply-chain issue in a tool it uses) inherits every credential it holds.
2. **No access at all.** Safe, but it just moves the work back onto a human, defeating the purpose of having an autonomous agent in the first place.

The pattern below is a third option: **zero standing access, plus a fast, low-friction way to grant access just-in-time, scoped to one task, for one bounded window, with a human in the loop on every grant.**

---

## 2. The concept

Treat the agent the way you'd treat a privileged human under a just-in-time access-control policy (the same category of pattern as Azure AD PIM, AWS's temporary elevated-access grants, or CyberArk-style vaulting — this is a lightweight, self-hosted implementation of that idea, not a directory-integrated identity platform):

- **Zero standing access.** By default, the agent holds no credential that authenticates it to any other machine.
- **The agent can request; it cannot grant.** It asks for access to a specific host, for a specific duration, with a stated reason. That request is just a message — it grants nothing by itself.
- **A human approves with one tap.** The request becomes a mobile notification with **Approve** and **Deny** actions. Nothing happens until the human acts.
- **Access takes the form of a short-lived certificate**, not a shared secret. Approving mints an SSH certificate, scoped to one identity/principal, valid for a bounded window (minutes to a few hours). It expires on its own — there is no key to revoke and no cleanup step.
- **A human-held break-glass credential exists per target, outside the agent's reach**, as a recovery path if the primary (certificate) path is ever unavailable.
- **Every step is logged**: every request, every approval, every denial, every signing event.

The load-bearing property: **fully compromising the agent is not sufficient to reach a target.** The agent can generate requests all day; without a human's physical approval action, no certificate is ever issued, and no target trusts any credential the agent already holds. Authority flows one direction only — from the human, through the signing authority, down to the agent. The signing authority never holds a credential that reaches back to the agent.

---

## 3. The user experience

### From the agent's side

```
$ request-access <target> <duration> "<reason>"
requested <target> for <duration> — waiting for approval...
```

The command blocks. If approved, it returns with a working, time-boxed credential in hand; the agent proceeds. If denied — or if nothing happens — it eventually times out with no credential. **Denied and ignored look identical to the agent.** It cannot tell whether a human actively rejected the request or simply hasn't looked yet. This is intentional: if the agent is ever the compromised party, it should learn nothing about whether it's being watched.

### From the human's side

A push notification arrives: *"Agent wants access to `<target>` for `<duration>`: `<reason>`"*, with two buttons, **Approve** and **Deny**. Tapping Approve is the entire interaction — no app to open, no terminal, no typing. Tapping Deny silently closes the request; no explanation is owed back to the agent about why.

### End to end

1. Agent requests access to a target, for a duration, with a reason.
2. Human gets a notification with Approve/Deny.
3. Human taps Approve.
4. A short-lived certificate is minted and delivered back to the agent.
5. The agent connects to the target using the certificate — the target has no other way in for this identity.
6. The certificate expires. Access is gone. Nothing to clean up.

---

## 4. Architecture

Three roles, deliberately separated so that no single compromised component grants target access:

```
   AGENT                      SIGNING AUTHORITY                    HUMAN
 ─ holds its own SSH keypair   ─ runs the certificate authority    ─ mobile notification app
 ─ can PUBLISH requests        ─ runs the approval daemon          ─ holds approve/deny authority
 ─ can READ signed certs       ─ holds ALL signing keys              (the tap)
 ─ CANNOT approve or sign      ─ holds NO credential pointing
                                 back at the agent
```

**Components:**

| Component | Role |
|---|---|
| **Agent host** | Runs the agent and a small CLI that requests and receives certificates. Holds one SSH keypair (its own identity) and no target credentials. |
| **CA host** | A dedicated, minimal machine. Runs the certificate authority (issues short-lived SSH certificates) and the approval daemon (turns requests into notifications, handles the approve/deny webhook, calls the CA to sign). This machine is the trust anchor — protect it accordingly, and give the agent no standing path into it either. |
| **Notification/transport channel** | Carries three message types: the agent's request, the actionable approval prompt, and the signed certificate coming back. A pub/sub notification service works well; three topics/channels with independent access control are the key structural requirement (see below). |
| **Target hosts** | Any machine the agent needs to reach. Each one trusts the CA's public key for user-certificate authentication and holds **no standing key for the agent** — a valid, unexpired certificate is the only way in. |
| **Human's phone** | Runs the notification app, subscribed to the approval channel, with the approve/deny actions wired to hit the approval daemon's webhook. |

**The three-channel access-control split is the mechanism that makes "the agent can ask but cannot approve" true by construction, not by convention:**

| Channel | Writer | Reader | Carries |
|---|---|---|---|
| requests | agent | CA | `{request_id, target, duration, reason, agent_pubkey}` |
| approvals | CA | human's phone | the actionable notification + a one-time approval token |
| certificates | CA | agent | `{request_id, certificate}` — the `request_id` lets the agent match a response to its own outstanding request |

The agent must **never** have read access to the approvals channel. That's what prevents it from ever seeing an approval token and forging a grant.

---

## 5. Build instructions

This section is deliberately tool-agnostic on some points and concrete on others. Any SSH certificate authority (`step-ca` is a solid free choice), any pub/sub notification service with per-topic ACLs and mobile push + actionable buttons (`ntfy` is a solid free choice, self-hosted), and any scripting language capable of an HTTP client/server can implement this.

### 5.1 Trust model setup

1. Stand up a dedicated CA host — small (1 vCPU / 512MB–1GB RAM is plenty), minimal OS, and crucially a machine the agent has **no standing access to** once built.
2. Install and initialize an SSH certificate authority on it. You need:
   - A CA keypair for signing **user** certificates (this is what gets distributed to targets).
   - A way to invoke "sign this public key as principal `X`, valid until `Y`" programmatically (a CLI or API call), gated behind whatever secrets the CA implementation requires.
3. Confirm signing works manually before wiring anything else: generate a test keypair, sign it, inspect the resulting certificate, and confirm it shows the expected principal and validity window. **A certificate with an empty or unset principal list is valid for any username on any trusting host — always explicitly scope the principal and verify the signed certificate actually carries it.**

### 5.2 Notification/transport channel

1. Self-host a pub/sub notification service with topic-level access control and support for actionable push notifications (buttons that fire an HTTP request on tap).
2. Create three topics and three least-privilege accounts, matching the table in Section 4:
   - `requests`: agent writes, CA reads.
   - `approvals`: CA writes, human's phone reads. (The tap itself doesn't go back over this channel — see 5.3's webhook description below: it POSTs directly to the approval daemon.)
   - `certificates`: CA writes, agent reads.
3. **The agent's account must have no access whatsoever to the `approvals` topic.** This is the single most important ACL in the system.
4. Install the notification app on the human's phone, log in as the phone account, subscribe to `approvals`, and send a test message to confirm delivery before building further.

### 5.3 The approval daemon

Runs on the CA host. Two responsibilities:

**A. Subscribe to the `requests` topic.** For each incoming request:

- Validate the target against an allowlist and the requested duration against a hard cap. Reject anything outside policy, and notify the human of the rejection (do not silently drop it). Each allowlist entry should also record which principal to sign for on that target — this is the target→principal mapping the signing step below relies on; without it, "scoped to the mapped principal" has nothing to look up.
- Generate a single-use, short-lived (e.g. 10-minute) approval token and store the request details against it, server-side only.
- Publish an actionable notification to the `approvals` topic with two buttons — **Approve** and **Deny** — each configured to POST the token to the daemon's own webhook, at `/approve` and `/deny` respectively.

**B. Serve a small webhook**, reachable only from the trusted network (or a VPN), handling:

- **`/approve`**: look up the token; if valid and unused, mark it consumed (tokens must be single-use — no replay), invoke the CA to sign a certificate for the request's public key, scoped to the mapped principal and capped at the requested duration, publish the resulting certificate to the `certificates` topic, and write an audit record (timestamp, target, duration, reason, request id, validity window, outcome).
- **`/deny`**: look up the token, mark it consumed, write an audit record for the denial. By default, publish nothing further — the agent will simply time out, same as an un-tapped request. Optionally, to let the agent's client exit early instead of waiting out its full timeout, publish a generic message to `certificates` (e.g. `{request_id, certificate: null}`) — the same shape you'd use for any other terminal non-issuance state (a validation rejection, a signing failure). Either way, the agent should never be able to tell *why* no certificate arrived — only that one didn't.
- Log every outcome (approve, deny, rejected, signing failure) to both a durable audit log and wherever your normal service logging goes. Treat the deny path with the same log-completeness bar as the approve path — it is easy to build and test approve repeatedly while deny goes completely unexercised.

### 5.4 The agent-side client

A small CLI or library the agent invokes:

1. Ensures it has its own SSH keypair (generate on first use if absent).
2. Publishes a request `{request_id, target, duration, reason, agent_pubkey}` to the `requests` topic, then blocks, polling (or subscribing to) the `certificates` topic, filtering by its own `request_id`.
3. On receiving a matching certificate, writes it alongside its keypair and returns success with the validity window.
4. Times out after a bounded wait (a few minutes is reasonable) if nothing arrives, exiting the same way whether the request was denied, rejected, or simply never seen.

Wire the agent's SSH client configuration so that connecting to a target uses the keypair plus whatever certificate is currently on disk, and set the client to use **only** that identity (not falling back to other keys) — with no valid certificate present, the connection should fail cleanly. That failure *is* the default-deny behavior working correctly, not a bug to route around.

### 5.5 Onboarding a target host

Per target, one-time setup, additive and reversible (safe to do over an existing admin session):

1. Create a dedicated service account for the agent's identity on that host — no password, no standing `authorized_keys` entries, only the group memberships/sudo rights it genuinely needs for its work there.
2. Install the CA's user-certificate public key as a trusted issuer for SSH authentication on that host, and point sshd at it via the standard OpenSSH `TrustedUserCAKeys` directive.
3. Validate the sshd configuration syntactically **before** reloading it, and keep a fallback session open while you do — a bad config plus a reload is how you lock yourself out.
   - Be aware some systems run sshd as a socket-activated service, where configuration is read fresh on each new connection rather than requiring a reload/restart at all. Check which kind you have before assuming a reload is necessary or safe.
4. Add the target to the approval daemon's allowlist and restart it.
5. Add the target's connection details to the agent's SSH client config, pointing at the certificate-based identity.
6. Verify: request access, approve it, confirm the certificate shows the expected principal and validity window, connect and confirm the identity you land as, then let the certificate expire and confirm the connection is refused afterward.

### 5.6 Break-glass recovery (per target)

Once the certificate path is verified working on a target, add a human-held recovery credential:

1. The human generates a keypair themselves, entirely outside any system the agent can read from — a password manager's key-generation feature, or an offline `ssh-keygen` run, works well. The private key is never written anywhere the agent can access it.
2. Only the **public** half is shared with the agent, over the same kind of one-way, agent-read-only channel used for other out-of-band secrets.
3. The agent installs that public key as the *sole* entry in the target's standing `authorized_keys` for its service account. If this target is being retrofitted onto the system rather than built fresh via 5.5 (which creates the account with no standing key to begin with), this step *replaces* whatever pre-existing key was there — never leave both a prior standing key and the break-glass key in place at once.
4. The matching private key is handed to the agent only if the certificate path itself becomes unavailable (the CA host down, the notification channel down, a target's trust configuration broken) — a deliberate, rare, human-initiated act, never a routine credential kept on hand.

Net result: no machine in the fleet holds a private key that lets the agent bypass the tap-to-approve gate, while the human retains a recovery path that doesn't depend on the CA's own uptime.

### 5.7 Network exposure

- The CA host should default-deny inbound traffic and allow exactly: administrative SSH, the notification service's port (restricted to the trusted network), and the approval webhook's port (also restricted to the trusted network, or reachable only over a VPN).
- **A request travels over the notification service, but a tap travels directly to the approval webhook — these are two different ports.** Make sure both are reachable from wherever the human will actually be tapping from (the trusted LAN, and any VPN subnet used off-network), or approvals will silently fail to arrive with no visible error on the request side.
- Target hosts need only their normal SSH port open to the agent; the agent host needs no inbound rules for this system at all — it only makes outbound calls.

### 5.8 Backup & recovery of the CA itself

- Back up the CA's complete state (keys, configuration, any password/secret files needed for unattended startup) to offline, encrypted storage — not onto the agent host, which is the one machine this design keeps deliberately isolated from the CA.
- Restoring onto a fresh host, with the same CA keys intact, requires no changes on any target — they trust the CA's public key, which hasn't changed.
- Optional hardening: also issue **host** certificates from the same CA so the agent can verify it's connecting to the genuine target, not just the reverse; and/or pin certificates to a source address so a leaked certificate can't be used from an unexpected network location.

---

## 6. Security properties

**What this defends against:** a compromised, buggy, or maliciously-instructed agent gaining *standing* access to other machines. The agent holds no target credentials by default; it cannot mint its own access; every elevation requires a human's physical action; access expires on its own; every step is logged.

**What this explicitly does not do:**

- It is not a hardened, internet-facing PKI system. It assumes a trusted network and a reasonably permissive security posture appropriate to a home lab or small trusted environment — not a production enterprise perimeter.
- It does not constrain what the agent can do **during** a valid certificate's lifetime. Within the granted principal's scope and the certificate's validity window, the agent has exactly the access that was approved — so scope principals and durations conservatively, and only grant elevated rights (root, container-runtime group membership, etc.) where the task genuinely requires them.
- The human's approval action is the one irreducible gate in the whole system. Protect the device and account used to approve accordingly (device lock, app-level authentication where available).

---

## 7. Optional future extensions

These are genuine gaps in a minimal build, listed neutrally — pursue any of them if your use case warrants it; none is required for the system to function as specified above.

- **Automate target onboarding.** Section 5.5 as written is a manual, per-machine walkthrough. Turning it into a single script or configuration-management role (Ansible or similar) removes the main scaling friction as a fleet grows.
- **Host certificates for targets.** Closes the gap where the agent trusts whatever's listening at a target's configured address, without cryptographic proof of the target's identity.
- **Source-address pinning on certificates**, so a certificate is only usable from the agent's actual host, bounding the impact of a leaked certificate.
- **A first-class off-network approval path** (reverse proxy + VPN in front of the notification service and the approval webhook), rather than treating off-LAN approval as a special case.
- **Proactive expiry notice.** As specified, an expired certificate is discovered only when the next connection attempt fails. A status callback or scheduled check could surface this before it's needed.
- **Multi-target certificates.** As specified, one certificate authorizes one target. A "broader session" grant — one certificate valid for a named group of targets — is a straightforward extension if a use case calls for it.
- **Automate the break-glass rollout itself** (Section 5.6) so it's generated and installed as part of onboarding a target, rather than as a separate manual pass afterward.
- **Out-of-band verification of the break-glass key install.** As specified, the agent itself installs the human-generated public key (5.6 step 3) — a compromised agent could silently substitute its own key during that install. Verifying the installed key's fingerprint through a channel the agent doesn't control would close that gap.
- **Off-CA audit log storage.** As specified, audit records live on the CA host itself, so a full CA compromise could rewrite that history. Shipping logs to a separate, append-only sink would remove that single point of tampering.
- **Explicit note on request-identifier and token randomness.** Approval tokens and `request_id`s should both be generated with cryptographically secure randomness — sequential or guessable values would weaken the single-use-token property the system leans on.
- **Externalize the target allowlist.** As specified, the allowlist (5.3) is naturally implemented as a literal in the approval daemon's source. A separate config file (YAML or similar) that the daemon reads at startup would decouple fleet changes from code changes, and scale better as the number of targets grows.
- **Tighten the human approver's notification-channel scope.** As specified, the human's client typically needs read-write access to the approval topic because narrower (read-only) subscription support varies by notification-app client. Worth revisiting for deployments with a stricter threat model, where the human's device having only the minimum access it needs matters more than it does in a homelab.

---

_This document specifies a pattern, not a product. It is intended to be sufficient — architecture, UX, and step-by-step build instructions — for a person or an AI coding agent to implement an independent instance of the same system from scratch, choosing their own concrete tools within the constraints above._
