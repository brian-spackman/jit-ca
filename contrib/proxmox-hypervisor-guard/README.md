# Optional Add-On: Proxmox Hypervisor Anti-Self-Reference, S0-Tag Taint Guard & Auto-Evacuation

> **Who needs this?** Most `airlock` deployments do **not** need this add-on. By default, `airlock-approver` ignores `/run/airlock/current-hypervisor` and `/run/airlock/s0-protected-hosts` if those files do not exist.
>
> Enable this add-on **only** if you run `airlock` (`VM 10002`) inside a VM on Proxmox VE (e.g., `optimuxprime` at `10.6.1.1` + `metroplex` at `10.6.1.2`) **and** you use `airlock` to issue admin certificates or gated secrets for those Proxmox hypervisors.

## Why It Exists

1. **Hypervisor Self-Reference Protection:** If `airlock` (`VM 10002`) is currently running on hypervisor `node-a`, and an automation agent requests SSH access to `node-a` to run hypervisor maintenance or reboot it, breaking `node-a` while `airlock` lives on it would sever the approval plane needed to fix `node-a`.
2. **Proxmox `s0`-Tag / `10xxx` Hypervisor Taint Guard (`S0-PROTECTED` Rule):** Any Proxmox hypervisor that hosts an `s0`-tagged guest or any VM/CT in the `10xxx` tier (such as `optimuxprime` hosting `airlock` `10002`, `constellation` `10003`, `gitea` `10004`, `ultramagnus` `10005`) is dynamically tainted as `S0-PROTECTED`. Non-`S0` agent approvers (e.g. `teletraan`, `arcee`) are mechanically blocked (`REJECT_S0_PROTECTED` / `SIGN_BLOCKED_S0_PROTECTED`) from approving access to any `S0-PROTECTED` hypervisor — only human `S0` stewards (`brian` / `brian-adm`, `UID 10001`) can approve access to an `S0-PROTECTED` node.

## How It Works

1. **Hypervisor Identity & S0 Taint Injection (`inject-host-identity.sh` -> `airlock-set-host`):**
   - Attached as a Proxmox VM hookscript (`qm set 10002 --hookscript local:snippets/inject-host-identity.sh`).
   - Whenever `VM 10002` boots or finishes live-migrating, the hosting Proxmox node queries `pvesh get /cluster/resources --type vm` for any running guest with tag `s0` or VMID `10000..19999`, and runs `qm guest exec` to write:
     - `/run/airlock/current-hypervisor` (`0444`) — the Proxmox node currently hosting `VM 10002`
     - `/run/airlock/s0-protected-hosts` (`0444`) — the newline-delimited list of Proxmox nodes currently hosting any `s0`/`10xxx` workload
2. **S0 Taint Enforcement (`airlock-approver.py`):**
   - If `is_s0_protected_target(target)` is True and `not is_s0_approver(approver)`, `airlock-approver` rejects the request immediately (`REJECT_S0_PROTECTED`) and also re-verifies at `/approve` time (`SIGN_BLOCKED_S0_PROTECTED`, HTTP `403`).
3. **Actionable `Evacuate & Mint` Prompt (`airlock-approver.py`):**
   - If `target == current_hypervisor()`:
     - Without `airlock-evacuate` installed, `airlock-approver` fails closed (`REJECT_SELF_HOST` / `SIGN_BLOCKED_SELF_HOST`).
     - With `/usr/local/libexec/airlock-evacuate` installed, the phone notification button changes to **`Approve: Evacuate & Mint`**.
   - When you tap **Approve: Evacuate & Mint**, `airlock-approver` invokes `airlock-evacuate <target>`, which calls the Proxmox API to live-migrate `VM 10002` to the peer hypervisor node, verifies `/run/airlock/current-hypervisor` updated to the peer node, and **only then** signs and delivers the SSH certificate for `<target>`.
