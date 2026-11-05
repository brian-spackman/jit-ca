# Airlock Ansible Playbooks & Roles (`airlock_server` & `airlock_target`)

This directory provides two idempotent Ansible playbooks and roles:

1. **`deploy-airlock.yml` (`roles/airlock_server`):** Provisions the Airlock server itself (`VM 1901`) — installs `step-ca`, `ntfy`, `ufw`, `qemu-guest-agent`, initializes the SSH CA and Day-0 `birth_key`, configures `/usr/local/bin/airlock-approver` and `airlock-approver.service`, and optionally installs the Proxmox hypervisor self-reference guard helpers (`airlock-set-host` and `airlock-evacuate`).
2. **`onboard-target.yml` (`roles/airlock_target`):** Onboards target Linux hosts/containers to trust the Airlock SSH User CA — creates the principal user (`airlock_principal_user`, default `airlock-admin`), configures passwordless sudo, installs `/etc/ssh/trusted_user_ca_keys`, writes `/etc/ssh/airlock_principals/<user>` with `<user>@<target>` (and any `approved-by-<approver>@<target>` entries from `airlock_allowed_approvers`), configures `/etc/ssh/sshd_config.d/10-airlock.conf`, optionally locks `~/.ssh/authorized_keys` to only the escrowed per-target break-glass key (`airlock_manage_authorized_keys: true`), and scrubs the Day-0 template `birth_key` (`airlock_purge_birth_pubkey`).

## Quick Start

```bash
cp inventory.example.yml inventory.yml
# 1. Provision or update the Airlock server:
ansible-playbook -i inventory.yml deploy-airlock.yml --check --diff
ansible-playbook -i inventory.yml deploy-airlock.yml

# 2. Onboard target hosts:
ansible-playbook -i inventory.yml onboard-target.yml --check --diff
ansible-playbook -i inventory.yml onboard-target.yml
```

## Day-0 Tap-to-Enroll (`airlock-enroll`)

When Proxmox VM/LXC templates are seeded with `/etc/airlock/secrets/birth_key.pub`, any agent can request zero-standing-access enrollment of a newly created container/VM:

```bash
airlock-enroll <target-hostname> <target-ip> "<reason>" [approver]
```

When approved on the designated approver's `ntfy` channel, `airlock-approver` automatically generates a fresh per-target `ed25519` break-glass keypair, escrows the private key (`0600`) to `/etc/airlock/secrets/break-glass/<target>.id_ed25519` (and/or `BREAK_GLASS_ESCROW_CMD`), runs `onboard-target.yml` over `birth_key`, scrubs `birth_key.pub` from the target, and persists `<target>` to `/etc/airlock/target-allowlist.txt`.
