#!/usr/bin/env bash
# ufw-rules.sh — canonical inbound firewall rules for the CA host (jit-ca).
#
# Run on the CA host (as root / via sudo) after a rebuild or when ufw is reset.
# Idempotent: `ufw allow` is a no-op if the identical rule already exists.
#
# Why this file exists: a hand-configured firewall is easy to get subtly wrong
# on the approve webhook (port 8081) — either missing the rule entirely, or
# allowing it only from the LAN so taps arriving over a VPN tunnel get dropped.
# Codifying the rules here so a rebuild can't silently lose them.
#
# See REPLICATION-GUIDE.md Section 8 (and the Known Gotchas section, 14) for
# the rationale and the gotcha about forgetting the webhook port.
set -euo pipefail

# PLACEHOLDER: set these to your actual subnets (LAN_CIDR from the guide).
# VPN_SUBNET is only needed if you'll approve from off-LAN (Section 4.4).
LAN_SUBNET="10.0.0.0/24"    # trusted LAN
VPN_SUBNET="10.5.0.0/24"    # VPN clients, for off-LAN approval (see Section 4.4)

# Ensure default-deny is in place before adding allow rules.
# Note: if SSH (port 22) is not allowed below, enabling ufw will lock you out.
ufw default deny incoming
ufw default allow outgoing

# SSH admin — restrict to specific hosts if your posture warrants it.
ufw allow 22/tcp comment "ssh admin"

# ntfy server — LAN clients + the local approver publish here.
# (The approver on this same box reaches ntfy via loopback, which ufw doesn't
# filter by default; this rule covers external LAN clients only.)
ufw allow from "$LAN_SUBNET" to any port 8080 proto tcp comment "ntfy (LAN)"

# Approve/Deny webhook. MUST allow BOTH subnets: the phone taps from the LAN
# and from the VPN tunnel when away. Dropping either silently breaks the Approve
# tap — the notification still arrives (8080), only the tap dies.
ufw allow from "$LAN_SUBNET" to any port 8081 proto tcp comment "jit-ca approve webhook (LAN)"
ufw allow from "$VPN_SUBNET" to any port 8081 proto tcp comment "jit-ca approve webhook (VPN)"

# Enable ufw (--force skips the interactive prompt; safe here because we
# explicitly allowed SSH above).
ufw --force enable

echo "Applied jit-ca ufw rules. Current status:"
ufw status verbose
