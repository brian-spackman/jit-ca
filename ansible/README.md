# Airlock Target Onboarding (Ansible)

Automates **Section 7 (Onboarding a target host)** and **Section 10 (Break-glass recovery)** of [`../REPLICATION-GUIDE.md`](../REPLICATION-GUIDE.md) idempotently across Debian/Ubuntu targets (including Debian 13+ socket-activated `ssh.socket`).

## What `roles/airlock_target` Does

1. **Creates the agent service user** (`airlock_principal_user`, default `agent`) with a locked password (`passwd -l`) and passwordless sudo (`/etc/sudoers.d/<user>`, validated via `visudo -cf`).
2. **Installs the SSH User CA public key** to `/etc/ssh/trusted_user_ca_keys` (`0644`).
3. **Binds the per-target principal** (`<user>@<target_hostname>`) in `/etc/ssh/airlock_principals/<user>` so a certificate minted for `target-a` is rejected by `target-b` and cannot authenticate as `root`.
4. **Installs `/etc/ssh/sshd_config.d/10-airlock.conf`**, validates syntax with `sshd -t`, and reloads `sshd` safely (skipping reload when `ssh.socket` socket-activation is active on Debian 13+).
5. **Optional Break-Glass Key Lockdown (`airlock_manage_authorized_keys: true`):** Replaces `~/.ssh/authorized_keys` with your offline/1Password break-glass public key (`airlock_break_glass_pubkey`) so no standing agent key remains on the box.
6. **Optional Proxmox Hypervisor Guard (`airlock_hypervisor_guard_enabled: false` by default):** Leave `false` for normal targets. See [`../contrib/proxmox-hypervisor-guard/`](../contrib/proxmox-hypervisor-guard/) if running `airlock` inside a multi-node Proxmox cluster where the CA VM also governs its own hypervisors.

## Quick Start

```bash
cp inventory.example.yml inventory.yml
# Edit inventory.yml with your target IP(s) and ssh_user_ca_key.pub
ansible-playbook -i inventory.yml onboard-target.yml --check --diff
ansible-playbook -i inventory.yml onboard-target.yml
```
