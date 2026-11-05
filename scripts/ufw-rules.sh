#!/usr/bin/env bash
# ufw-rules.sh — canonical inbound firewall rules for the Airlock host.
#
# Run on the Airlock host (as root / via sudo) after a rebuild or when ufw is reset.
# Idempotent: `ufw allow` is a no-op if the identical rule already exists.
#
# See REPLICATION-GUIDE.md Section 8 (and the Known Gotchas section, 14) for
# the rationale and the gotcha about forgetting the webhook port.
set -euo pipefail

# PLACEHOLDER: set these to your actual subnets (LAN_CIDR from the guide).
# VPN_SUBNET is only needed if you'll approve from off-LAN (Section 4.4).
LAN_SUBNET="10.0.0.0/24"    # trusted LAN
VPN_SUBNET="10.5.0.0/24"    # VPN clients, for off-LAN approval (see Section 4.4)

ufw default deny incoming
ufw default allow outgoing

# SSH admin — restrict to specific hosts if your posture warrants it.
ufw allow from "$LAN_SUBNET" to any port 22 proto tcp comment "ssh admin (LAN)"
ufw allow from "$VPN_SUBNET" to any port 22 proto tcp comment "ssh admin (VPN)"

# ntfy server — LAN clients + the local approver publish here.
ufw allow from "$LAN_SUBNET" to any port 8080 proto tcp comment "ntfy (LAN)"
ufw allow from "$VPN_SUBNET" to any port 8080 proto tcp comment "ntfy (VPN)"

# Approve/Deny webhook. MUST allow BOTH subnets: the phone/approver taps from the LAN
# and from the VPN tunnel when away.
ufw allow from "$LAN_SUBNET" to any port 8081 proto tcp comment "airlock approve webhook (LAN)"
ufw allow from "$VPN_SUBNET" to any port 8081 proto tcp comment "airlock approve webhook (VPN)"

ufw --force enable

echo "Applied airlock ufw rules. Current status:"
ufw status verbose
