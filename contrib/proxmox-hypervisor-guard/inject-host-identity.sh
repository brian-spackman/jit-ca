#!/usr/bin/env bash
# Proxmox VE VM hookscript for the Airlock VM (e.g. VM 1901).
# Attach via: qm set 1901 --hookscript local:snippets/inject-host-identity.sh
#
# On post-start (initial boot or live migration completion), injects the hosting
# Proxmox node's short hostname into the Airlock VM via qemu-guest-agent so
# airlock-approver can prevent un-evacuated self-referential hypervisor changes.
set -euo pipefail

VMID="$1"
PHASE="$2"

if [[ "$PHASE" == "post-start" ]]; then
    HOST_NODE="$(hostname -s)"
    # Best-effort retry loop while qemu-guest-agent settles inside the VM
    for _ in 1 2 3 4 5; do
        if qm guest exec "$VMID" -- /usr/local/libexec/airlock-set-host "$HOST_NODE" >/dev/null 2>&1; then
            exit 0
        fi
        sleep 1
    done
fi
