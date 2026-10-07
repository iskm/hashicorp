# Vault hardening and verification

For an EXISTING initialized primary Vault cluster on dedicated Linux/systemd
nodes. Requires Ansible Core 2.19+, Python 3.8+ on nodes, become privileges,
existing Vault service/binary/account, and certificate-valid direct HTTPS access.
Debian/Ubuntu and RHEL-family package names are supported. No initialization,
peer membership mutation, config replacement or Vault upgrade is performed.

## Run

Run from the extracted vault-hardening directory:

1. Copy inventory.example.yml to inventory.yml; fill SSH addresses, DIRECT node
   HTTPS URLs and actual Raft IDs. Every primary-cluster node belongs in inventory.
2. Edit group_vars/vault_nodes.yml: paths, service/account, API URL, CA path,
   storage type, expected voters and approved patched version floor. The example
   minimum release is a placeholder, not a statement of current security.
3. Copy and encrypt the example input file:

```bash
cp vars/secrets.example.yml vars/secrets.yml
chmod 600 vars/secrets.yml
# Edit locally to supply the administrative token and threshold Shamir shares.
ansible-vault encrypt vars/secrets.yml
ansible-playbook -i inventory.yml site.yml --ask-vault-pass -e vault_mode=verify
ansible-playbook -i inventory.yml site.yml --ask-vault-pass \
  -e vault_mode=apply -e vault_restart_allowed=true
ansible-playbook -i inventory.yml site.yml --ask-vault-pass -e vault_mode=verify
```

The first verify run may fail on an unhardened deployment. It is fail-fast and
prints sanitized node checks; it is not a comprehensive vulnerability scanner.
`--check` is rejected: use vault_mode=verify. Verify makes no persistent hardening
changes; Ansible still transfers a temporary verification script over SSH.

Apply processes hosts serially, restarts only when the service override changes,
and stops if a node fails. All nodes must initially be initialized/unsealed.
Shamir threshold shares are required BEFORE any node changes. For KMS/HSM leave
vault_unseal_keys empty: recovery keys cannot perform ordinary auto-unseal.
Clear partial Shamir unseal attempts out of band before maintenance. A restart
of the active node can cause brief request failures; clients must retry.

## Credentials

`include_vars` loads vars/secrets.yml (override vault_secrets_file as needed).
`vault_admin_token` may be a bootstrap ROOT TOKEN; the internal root encryption
key is not a login credential. Prefer a short-lived administrative token with
required sudo capabilities. Token/share tasks use no_log, no cacheable facts,
and HTTPS headers/bodies rather than command-line secret arguments. No token
helper or Vault login file is created. Protect the Ansible controller and temp
files; avoid debug tracing and untrusted callbacks. Keep production unseal-share
custody separate and remove shares from this maintenance file afterward.

All API calls use the root namespace. The token needs read/sudo access to
sys/audit, sys/config/state/sanitized, sys/storage/raft/configuration,
sys/storage/raft/autopilot/state and selected sys/auth mount paths, and update
access to the chosen audit mount and auth tuning paths when applying. Exact
least-privilege policies should be reviewed against your release and scope.
The bundle does not revoke its own credential. Establish/test non-root admin
authentication, then revoke the bootstrap root token out of band. Subsequent
runs need a new administrative token.

## Coverage

| Control | Applied | Verified |
|---|---|---|
| Non-root service | Existing service account in systemd | Live UID/account |
| Minimal writes | Root-owned binary/config/key and protected config dir | Kernel write checks as service account, parent dirs and modes |
| Storage access | Private top-level Raft directory | Ownership/mode/write access |
| TLS | Existing configuration retained | Direct CA/hostname validation and TLS1.2+ handshake; active listeners enabled/minimum TLS1.2+ |
| Swap | swapoff, fstab comments, mask discovered swap units | No live/fstab swap |
| Core dumps | LimitCORE=0 and fs.suid_dumpable=0 | Unit and live process limits |
| systemd sandbox | Official package-style restrictions, UMask, NOFILE, MEMLOCK | Unit settings and live NoNewPrivs |
| Clock | Optional chrony installation | NTPSynchronized=yes |
| Audit | Dedicated file audit mount after directories exist on all nodes | Mount/path/hashing and private file on all nodes |
| Rotation | logrotate with SIGHUP reopen, no copytruncate | Config existence and debug parse |
| Raft | No membership changes | Expected voters/IDs, one leader, healthy Autopilot, failure tolerance >=1 |
| Lockout | Optional selected mount tuning | Threshold/duration/reset/disable readback |
| Release floor | No upgrades | Operator-selected minimum version |
| HSTS | No listener rewrite | Optional direct response header check |
| MAC | No policy changes | Optional SELinux/AppArmor facility activity |

Lockout defaults to no selected mounts/no mutation. To use, select EXISTING mounts
in vault_lockout_mounts and set vault_manage_lockout=true. Only userpass/approle/
ldap support lockout. Desired durations are integer SECONDS; API writes use
seconds duration strings. Global environment overrides must be reviewed too.

TLS checks attest specified endpoints; they do not prove every standby port
rejects obsolete protocols. Sanitized config calls may forward to the active
node and attest its config only. Config files are protected but not parsed or
rewritten; all service -config paths must be beneath vault_config_dir. Actual
process arguments are inspected. Other config/environment paths and plugins
need separate review. File permissions cover configured paths, not every path
writable by the Vault account. `disable_mlock` is left unchanged: choose memory
locking appropriate to Raft/mmap and capacity, independently of swap removal.
PrivateDevices may affect hardware HSMs; validate service sandbox compatibility.

Raft defaults target conventional 3+ voter primary clusters, not single-node,
2-node or redundancy-zone designs. External-storage mode skips Raft checks;
external provider health, ACLs and TLS need separate checks. Enterprise namespaces
and replication secondaries are outside this bundle. Verify node DNS corresponds
to the declared Raft IDs; the bundle does not prove their physical identity.

Existing conflicts at the managed audit mount fail instead of disabling a device.
Unrelated audit devices are preserved. Ensure all nodes have free space and
correct MAC labels. File existence/modes do not prove every standby audit write
path or centralized delivery. Use a second independent audit device and test
rotation/logging in staging. Vault may refuse requests when no enabled audit
device can record them. Monitor audit errors and disk capacity. Ensure logrotate
is scheduled through cron/timer and reconcile competing stanzas; parsing its
configuration does not prove scheduling.

## Deployment-specific controls still required

- Restrict ingress API 8200 to approved clients/admins and cluster 8201 to peers;
  preserve maintenance SSH. Restrict egress to approved DNS/NTP, storage, seal,
  databases/identity providers and other dependencies. For Kubernetes auth,
  EVERY Vault node needs TokenReview API connectivity and CA trust, including
  EKS NAT/private endpoint routing. No firewall/security-group replacement occurs.
- Verify client-to-LB, LB-to-Vault and external-storage TLS; expiry/SAN/renewal and
  cipher policy. Prefer TLS1.3 where compatible. Manage listeners through your
  existing deployment role; do not append duplicate listener stanzas.
- Single tenancy, console/SSH access, least-privilege policies, short TTLs,
  offboarding/token and lease revocation, upgrade cadence/security advisories,
  immutable rebuilds, approved plugins, centralized logs/alerts.
- Seal credential protection: prefer workload/instance identity for KMS; inspect
  configuration and environment-file permissions for plaintext credentials.
  This bundle does not read or print seal secrets for inspection.
- Review all configuration files and runtime overrides. Set
  deny_slash_in_templated_paths=true through your config role where compatible;
  review unauthenticated metrics/profiling/in-flight logging on every node.
- Verify dedicated storage capacity/partition and Vault-specific MAC policy.
  Optional MAC validation checks OS activity, not policy confinement for Vault.
- Remove zram/cloud-init/other swap generators. Reboot and re-run verification
  to prove persistence beyond fstab and discovered systemd units.
- Avoid command history containing Vault secrets. This play uses APIs and does
  not rewrite operator profiles/history.

## Failure and rollback

Take/test a snapshot with your established backup procedure first. Stage the
permissions, sandbox, plugins/HSM behavior and rolling maintenance first. No
automatic rollback is performed. If a node fails, inspect its journal and
permissions, restore prior approved unit configuration if necessary, reload
systemd, start/unseal the node and verify before continuing. The override lives
at /etc/systemd/system/<service>.service.d/90-hardening.conf. Fstab edits create
an Ansible backup. Reverting settings or disabling audit devices blindly could
compound a failure. The bundle does not copy snapshot secret data to the controller.

## Validation

Ansible syntax, YAML parsing, Python compilation, inventory parsing and two mocked
verification failure-path checks were performed. No real Vault cluster was available;
API responses, restart/unseal, service compatibility and rotation require staging
validation against your installed release.

## Sources

- https://developer.hashicorp.com/vault/docs/concepts/production-hardening
- https://developer.hashicorp.com/vault/docs/configuration/listener/tcp
- https://developer.hashicorp.com/vault/api-docs/system/config-state
- https://developer.hashicorp.com/vault/api-docs/system/audit
- https://developer.hashicorp.com/vault/docs/audit/file
- https://developer.hashicorp.com/vault/api-docs/system/auth
- https://developer.hashicorp.com/vault/api-docs/system/storage/raft
- https://developer.hashicorp.com/vault/api-docs/system/storage/raftautopilot
