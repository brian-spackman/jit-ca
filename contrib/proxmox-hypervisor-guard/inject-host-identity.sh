#!/usr/bin/env bash
# Proxmox VE VM hookscript for the Airlock VM (e.g. VM 10002).
# Attach via: qm set 10002 --hookscript local:snippets/inject-host-identity.sh
#
# On post-start (initial boot or live migration completion):
# 1. Injects the hosting Proxmox node's short hostname into /run/airlock/current-hypervisor
# 2. Scans cluster/local VM & LXC resources for any running S0 guest (tag `s0` or VMID 10000..19999)
#    and injects the list of S0-tainted Proxmox nodes into /run/airlock/s0-protected-hosts
#    so airlock-approver mechanically blocks non-S0 (agent) approvals targeting any S0 hypervisor.
set -euo pipefail

VMID="$1"
PHASE="$2"

detect_s0_nodes() {
    if command -v pvesh >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        pvesh get /cluster/resources --type vm --output-format json 2>/dev/null | python3 -c '
import json, sys
try:
    items = json.load(sys.stdin)
except Exception:
    items = []
nodes = set()
for it in items:
    if it.get("status") != "running":
        continue
    vmid = int(it.get("vmid") or 0)
    tags = [t.strip().lower() for t in str(it.get("tags") or "").replace(",", ";").split(";") if t.strip()]
    if (10000 <= vmid <= 19999) or ("s0" in tags):
        node = str(it.get("node") or "").strip().lower()
        if node:
            nodes.add(node)
print(",".join(sorted(nodes)))
' || true
    fi
}

if [[ "$PHASE" == "post-start" ]]; then
    HOST_NODE="$(hostname -s)"
    S0_NODES="$(detect_s0_nodes)"
    if [[ -z "$S0_NODES" && "$VMID" -ge 10000 && "$VMID" -le 19999 ]]; then
        S0_NODES="${HOST_NODE,,}"
    fi
    # Best-effort retry loop while qemu-guest-agent settles inside the VM
    for _ in 1 2 3 4 5; do
        if qm guest exec "$VMID" -- /usr/local/libexec/airlock-set-host "$HOST_NODE" --s0-hosts "$S0_NODES" >/dev/null 2>&1; then
            exit 0
        fi
        sleep 1
    done
fi
