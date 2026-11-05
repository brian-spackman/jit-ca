# Optional Add-On: Proxmox Hypervisor Anti-Self-Reference & Auto-Evacuation Guard

> **Who needs this?** Most `jit-ca` deployments do **not** need this add-on. By default, `jit-ca-approver` ignores `/run/jit-ca/current-hypervisor` if the file does not exist.
>
> Enable this add-on **only** if you run `jit-ca` inside a VM on a multi-node Proxmox VE cluster (e.g., `optimuxprime` + `metroplex`) **and** you also use `jit-ca` to issue admin certificates for those same Proxmox hypervisors.

## Why It Exists

If `jit-ca` (`VM 1901`) is currently running on hypervisor `node-a`, and an automation agent requests SSH access to `node-a` to run hypervisor maintenance or reboot it, breaking `node-a` while `jit-ca` lives on it would sever the approval plane needed to fix `node-a`.

## How It Works

1. **Hypervisor Identity Injection (`inject-host-identity.sh` -> `jit-ca-set-host`):**
   - Attached as a Proxmox VM hookscript on both cluster nodes (`qm set 1901 --hookscript local:snippets/inject-host-identity.sh`).
   - Whenever `VM 1901` boots or finishes live-migrating, the hosting Proxmox node runs `qm guest exec` to write its hostname into `/run/jit-ca/current-hypervisor` (`0444`) inside the `jit-ca` VM.
2. **Actionable `Evacuate & Mint` Prompt (`jit-ca-approver.py`):**
   - If `target == current_hypervisor()`:
     - Without `jit-ca-evacuate` installed, `jit-ca-approver` fails closed (`REJECT_SELF_HOST` / `SIGN_BLOCKED_SELF_HOST`).
     - With `/usr/local/libexec/jit-ca-evacuate` installed, the phone notification button changes to **`Approve: Evacuate & Mint`**.
   - When you tap **Approve: Evacuate & Mint**, `jit-ca-approver` invokes `jit-ca-evacuate <target>`, which calls the Proxmox API to live-migrate `VM 1901` to the peer hypervisor node, verifies `/run/jit-ca/current-hypervisor` updated to the peer node, and **only then** signs and delivers the SSH certificate for `<target>`.
