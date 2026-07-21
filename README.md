# Homelab JIT-CA — just-in-time SSH for your AI agent

> Give an AI agent the ability to work on your other machines **without** giving it standing keys to them. Default-deny everywhere; a single tap on your phone grants short-lived, scoped, auto-expiring access for one task. It's the just-in-time privileged-access pattern enterprise IAM tools (Azure PIM, AWS JIT access, CyberArk, etc.) use for humans, rebuilt for a self-hosted home lab out of `step-ca`, `ntfy`, and `ssh` certificates — a signing CA, not a directory-integrated identity platform.

## What's in this repo

Three documents — this README, the [replication guide](./REPLICATION-GUIDE.md), and a [leaner standalone spec](./JIT-CA-SPEC.md) — covering the concept, the experience, and step-by-step build instructions in enough detail to implement your own instance from scratch. The [`scripts/`](./scripts/) directory contains sanitized reference implementations of the four core files: the approval daemon (`jit-ca-approver.py`), its systemd unit (`jit-ca-approver.service`), the agent-side request CLI (`jit-request`), and the CA host firewall script (`ufw-rules.sh`). Every deployment-specific value (IPs, hostnames, principal name, ntfy URL) is replaced with a clearly-marked placeholder comment; see the PLACEHOLDER lines near the top of each file.

## The problem

If you run an AI coding/ops agent (Claude Code, an opencode session, whatever) on a box in your network, sooner or later it needs to *do something on another machine* — upgrade a container on the Docker host, poke at the NAS, restart a service. You have two bad options:

1. **Give the agent standing SSH keys to everything.** Now the single most prompt-injectable, most experimental process in your house holds persistent credentials to your whole fleet. Compromise the agent and you've compromised everything it can reach.
2. **Give it nothing and do every cross-machine step by hand.** Safe, but it defeats the point of having an agent — you're back to being the one typing `ssh`.

Sandboxing the agent is the right instinct. But a sandbox that can never reach anything is just a box. What you actually want is the same thing you want for a privileged *human*: no standing access, and a fast, auditable way to elevate *just in time* for a specific task.

## The idea

Treat the agent like a privileged employee under just-in-time access control:

- **Zero standing access.** By default the agent has no credential that opens any target.
- **It can request, but it cannot grant.** The agent asks for access to a specific host, for a specific duration, with a stated reason.
- **You approve with one tap.** The request lands as a notification on your phone with **Approve** / **Deny** buttons. Nothing happens until you tap.
- **Access is a short-lived certificate.** Approving mints an SSH certificate scoped to one principal, valid for minutes to a few hours. It expires on its own. There is nothing to revoke and nothing to clean up.
- **A human-held break-glass key, per target.** You generate a keypair yourself (e.g. in a password manager), share only the *public* half with the agent to install, and keep the private half entirely off the agent's reach. It's handed over only if the tap-to-sign path itself is ever broken — a deliberate, rare act, not a standing credential.
- **Everything is logged.** Every request, approval, denial, and signing is on the record.

The crucial property: **compromising the agent is not enough to reach a target.** The agent can spam requests all day; without your physical tap on the phone, no certificate is ever signed. Authority only ever flows *downward* — the box that holds the signing keys never holds any credential pointing back at the agent.

## How it works (the 30-second version)

```
  agent box                CA box (zero-trust anchor)            your phone
 ┌──────────┐   request   ┌───────────────────────────┐  notify  ┌─────────┐
 │          │ ──────────► │ approver daemon            │ ───────► │ Approve │
 │ agent    │             │  └─ mints 1-use token,     │          │  / Deny │
 │ (no creds│             │     pushes notification    │ ◄─────── └─────────┘
 │  to tgts)│             │  └─ on tap: step-ca signs  │   tap
 │          │ ◄────────── │     a short-lived SSH cert │
 └────┬─────┘   signed    └───────────────────────────┘
      │         cert
      │  ssh (cert-only) ───────────►  target host  (trusts the CA; no agent key on it)
      ▼
   does the task, cert expires, access evaporates
```

1. The agent runs `jit-request <host> <duration> "<reason>"`. This publishes a request and then blocks, waiting for a certificate.
2. An **approver daemon** on the CA box turns that into an actionable phone notification with a single-use, time-limited token behind the **Approve** button.
3. You tap **Approve**. Your phone — and only your phone — sends the token to the approver.
4. The approver verifies the token and asks `step-ca` to sign an SSH certificate for the agent's key, scoped to the principal/user you've mapped and capped at the requested TTL.
5. The certificate comes back to the agent over the same notification channel (it's a signed *public* key — not a secret), the agent SSHes in on it, does the task, and the cert expires.

The target hosts hold **no key for the agent** — ever. They simply trust the CA. A valid, unexpired certificate is the *only* way in, so "no cert" automatically means "no access."

**Deny is deliberately boring.** Tapping Deny logs the denial and burns the token — but the agent's own view of a denied request is identical to a request nobody ever tapped: no cert ever arrives, and it eventually times out. The agent has no way to distinguish "a human looked at this and said no" from "nobody's looked yet," which matters if the agent itself is ever the compromised party — it never learns whether it's actively being watched and blocked.

## Why it's worth it

- **Zero-friction once set up.** Day to day, the agent just says what it needs and you tap a button. No keys to rotate, no access to remember to revoke, no `authorized_keys` to prune. The cert's expiry *is* the cleanup.
- **The blast radius of a compromised agent is one tap, not your whole network.** This is the property that makes it sane to run an experimental, internet-fed agent at home and still let it touch real machines.
- **It scales to the whole fleet.** Onboarding a new machine is "create a service user + trust the CA" — a step you can bake into a VM/container template so every new box is cert-ready from first boot (today it's still a manual ~30-minute walkthrough per box, not yet templated — see limitations below).
- **You get an audit trail for free.** Who asked for what, when, why, and whether you approved — all logged, because every elevation goes through one chokepoint you control.

## Where it stands — v1, live today

This isn't a paper design — it's running. Every machine in a small home lab fleet is cert-only through this system, each with its own human-held break-glass key as the sole fallback. No machine holds a standing key that lets the agent bypass the tap.

## Known limitations & v2 scope

Honest gaps, not a roadmap fantasy — this is what a working v1 still lacks:

- **Onboarding is manual.** Trusting the CA, allowlisting a target, wiring the SSH config — all by hand, per box, every time. It should be one script or an Ansible role.
- **No host certs.** The agent verifies *its own* identity to targets, but not the reverse — it trusts whatever's listening at a target's IP. Host certs from the same CA would close this; not load-bearing for the threat model today, but a real gap.
- **No source-address pinning.** A leaked cert works from anywhere on the trusted network, not just from the agent's actual host.
- **Off-LAN approval is a bolt-on, not a default.** Approving from outside the LAN needs a reverse proxy + VPN path that most setups won't have configured out of the box.
- **Cert expiry is silent.** The agent discovers an expired cert by having its SSH attempt fail — there's no proactive "your access just lapsed" signal.
- **Untested paths hide bugs, even in a system that "works."** It's easy to build and repeatedly exercise the Approve path while Deny goes completely unexercised until it's needed for real — and a code path nobody has tapped is exactly where a logging gap or silent failure can hide. **Treat any control path you haven't personally tested end-to-end as unverified, not as working by inheritance from the paths you have tested.**
- **The target allowlist is hardcoded in the approver script**, not externalized to a config file. `TARGET_ALLOWLIST` currently lives as a Python literal in `jit-ca-approver.py`. For a single-digit fleet that's fine, but it should really be a separate YAML (or similar) file the script reads at startup — easier to manage as the fleet grows, and it means changing the allowlist doesn't require touching code.
- **The phone's ntfy subscription has read-write access, not read-only.** It wasn't obvious how to get a read-only subscription working in the ntfy app for the approvals topic, so the `phone` account was granted read-write for simplicity (Section 4.2/4.3 of the replication guide). That's a reasonable call for a homelab, but it's broader than the phone strictly needs — worth tightening if you're deploying this somewhere with a stricter threat model.
- **Reference scripts are in [`scripts/`](./scripts/).** The real implementation, sanitized: approval daemon, systemd unit, agent CLI, and firewall script, each with PLACEHOLDER comments marking values to fill in for your deployment.

## Read next

- **[REPLICATION-GUIDE.md](./REPLICATION-GUIDE.md)** — the complete, reproducible build: the SSH CA, the approval daemon, the notification channel, the firewall posture, target onboarding, and a Known Gotchas section covering the failure modes most likely to bite you.
- **[JIT-CA-SPEC.md](./JIT-CA-SPEC.md)** — a leaner, tool-agnostic version of the same build: one self-contained document (concept, UX, architecture, and step-by-step instructions) with the narrative detail stripped out, sized to hand to a coding agent as a build spec.

---

_This is a self-hosted home-lab pattern, not a product. It assumes a trusted LAN and is deliberately lightweight. See the replication guide for the threat model and where it stops._
