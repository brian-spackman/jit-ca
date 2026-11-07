# Airlock Ansible Playbooks & Roles (`airlock_server` & `airlock_target`)

This directory provides two idempotent Ansible playbooks and roles:

1. **`deploy-airlock.yml` (`roles/airlock_server`):** Provisions the Airlock server itself (`VM 10002` at `10.6.10.2`; `10.6.10.1` / `10001` is reserved for the human `S0` steward `brian-adm` `UID 10001`) — installs and configures **OpenBao** (`openbao` user/group at **`UID/GID 10302`**, `/etc/openbao/openbao.hcl`, `/var/lib/openbao/data`, and `/usr/local/libexec/airlock-openbao-bootstrap` for `ssh-client-signer/`, `secret/` `kv-v2`, and `transit/`), `ntfy`, `ufw`, `qemu-guest-agent`, Day-0 `birth_key`, `/usr/local/bin/airlock-approver`, `airlock-approver.service`, and optional Proxmox hypervisor guard helpers (`airlock-set-host` and `airlock-evacuate`). Also supports `airlock_ca_backend: "step-ca"` for legacy `step-ca` deployments.
2. **`onboard-target.yml` (`roles/airlock_target`):** Onboards target Linux hosts/containers to trust the Airlock SSH User CA — creates the principal user (`airlock_principal_user`, default `airlock-admin`), configures passwordless sudo, installs `/etc/ssh/trusted_user_ca_keys`, writes `/etc/ssh/airlock_principals/<user>` with `<user>@<target>` (and any `approved-by-<approver>@<target>` entries from `airlock_allowed_approvers`), configures `/etc/ssh/sshd_config.d/10-airlock.conf`, optionally locks `~/.ssh/authorized_keys` to only the escrowed per-target break-glass key (`airlock_manage_authorized_keys: true`), and scrubs the Day-0 template `birth_key` (`airlock_purge_birth_pubkey`).

## Quick Start

```bash
cp inventory.example.yml inventory.yml
# 1. Provision or update the Airlock server (VM 10002 / 10.6.10.2):
ansible-playbook -i inventory.yml deploy-airlock.yml --check --diff
ansible-playbook -i inventory.yml deploy-airlock.yml

# 2. Once OpenBao is initialized and unsealed, bootstrap its SSH CA, kv-v2, transit, and approver token:
sudo OPENBAO_ADMIN_TOKEN_FILE=/etc/openbao/root.token /usr/local/libexec/airlock-openbao-bootstrap

# 3. Onboard target hosts:
ansible-playbook -i inventory.yml onboard-target.yml --check --diff
ansible-playbook -i inventory.yml onboard-target.yml
```

## Day-0 Tap-to-Enroll (`airlock-enroll`)

When Proxmox VM/LXC templates are seeded with `/etc/airlock/secrets/birth_key.pub`, any agent can request zero-standing-access enrollment of a newly created container/VM:

```bash
airlock-enroll <target-hostname> <target-ip> "<reason>" [approver]
```

When approved on the designated approver's `ntfy` channel, `airlock-approver` automatically generates a fresh per-target `ed25519` break-glass keypair, escrows the private key fail-closed to OpenBao `kv-v2` (`secret/data/break-glass/<target>`), 1Password (`BREAK_GLASS_ESCROW_CMD`), and `/etc/airlock/secrets/break-glass/<target>.id_ed25519` (`0600`), runs `onboard-target.yml` over `birth_key`, scrubs `birth_key.pub` from the target, and persists `<target>` to `/etc/airlock/target-allowlist.txt`.

## Gated Secret Release via OpenBao Cubbyhole Response-Wrapping (`airlock-request --secret`)

In addition to short-lived SSH certificates, agents or boot hooks can request gated secrets stored in OpenBao `kv-v2` (such as encrypted ZFS dataset passphrases at `secret/data/zfs/<host>`):

```bash
# Returns a 60s single-use OpenBao wrap_token (or unwraps directly if AIRLOCK_UNWRAP_ADDR is set):
airlock-request --secret metroplex zfs/metroplex "unlock encrypted ZFS pool on boot" brian
```

When approved, `airlock-approver` reads the secret from OpenBao with `X-Vault-Wrap-TTL: 60s` and publishes **only** the single-use `wrap_token` (`wrap_info.token`) to `airlock-certs`. The plaintext secret never crosses `ntfy`.
