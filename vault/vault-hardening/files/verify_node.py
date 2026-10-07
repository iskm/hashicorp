#!/usr/bin/env python3
"""Read-only checks. Never accepts/prints a Vault token or an unseal share."""
import http.client
import json
import os
import pwd
import re
import socket
import ssl
import stat
import subprocess
import sys
from urllib.parse import urlsplit

(service, user, binary, config, data, key, audit, url, ca, minimum,
 require_hsts, require_mac, storage) = sys.argv[1:]
checks = []

def record(name, ok, detail=''):
    checks.append({'check': name, 'passed': bool(ok), 'detail': detail})

def command(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=20)
    return p.returncode, p.stdout.strip()

def writable(path):
    # Kernel access check as the actual service user includes supplementary groups and ACLs.
    account = pwd.getpwnam(user)
    def demote():
        os.initgroups(user, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    p = subprocess.run([sys.executable, '-c',
                        'import os,sys; sys.exit(0 if os.access(sys.argv[1],os.W_OK) else 1)', path],
                       preexec_fn=demote, timeout=10)
    return p.returncode == 0

try:
    account = pwd.getpwnam(user)
    rc, output = command(['systemctl', 'show', service + '.service',
                          '--property=User,MainPID,LimitCORE,LimitNOFILE,NoNewPrivileges,PrivateTmp,PrivateDevices,ProtectSystem,ProtectHome,UMask,ActiveState'])
    props = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    record('service_account', rc == 0 and props.get('User') == user and account.pw_uid != 0)
    record('service_running', props.get('ActiveState') == 'active')
    for prop, expected in [('LimitCORE', '0'), ('NoNewPrivileges', 'yes'),
                           ('PrivateTmp', 'yes'), ('PrivateDevices', 'yes'),
                           ('ProtectSystem', 'full'), ('ProtectHome', 'read-only'), ('UMask', '0077')]:
        record('systemd_' + prop, props.get(prop) == expected, props.get(prop, 'missing'))
    record('file_descriptor_limit', props.get('LimitNOFILE', '').isdigit() and int(props['LimitNOFILE']) >= 65536)
    pid = int(props.get('MainPID', '0'))
    if pid:
        with open('/proc/%s/status' % pid) as f:
            status = dict(line.split(':', 1) for line in f if ':' in line)
        record('live_process_nonroot', int(status['Uid'].split()[0]) == account.pw_uid)
        record('live_process_no_new_privileges', status.get('NoNewPrivs', '').strip() == '1')
        with open('/proc/%s/limits' % pid) as f:
            limits = f.read()
        record('live_core_limit_zero', re.search(r'^Max core file size\s+0\s+0\s+', limits, re.M))
        with open('/proc/%s/cmdline' % pid, 'rb') as f:
            args = f.read().decode().split('\0')
        paths = [a.split('=', 1)[1] for a in args if a.startswith('-config=')]
        paths += [args[i+1] for i, a in enumerate(args[:-1]) if a == '-config']
        record('all_config_paths_in_checked_directory', bool(paths) and all(
            os.path.commonpath([os.path.realpath(config), os.path.realpath(p)]) == os.path.realpath(config)
            for p in paths), 'Adjust vault_config_dir to match the service -config paths.')
    for path, name in [(binary, 'binary'), (config, 'configuration_directory'), (key, 'tls_private_key')]:
        s = os.stat(path)
        record(name + '_root_owned', s.st_uid == 0)
        record(name + '_not_service_writable', not writable(path))
        if name == 'tls_private_key':
            record('private_key_no_world_access', stat.S_IMODE(s.st_mode) & 7 == 0)
        # A non-writable executable/file can still be replaced through a writable parent.
        parent = os.path.dirname(os.path.realpath(path))
        safe = True
        while parent != '/':
            safe = safe and not writable(parent)
            parent = os.path.dirname(parent)
        record(name + '_ancestors_not_service_writable', safe)
    found = 0
    safe_config = True
    for root, dirs, files in os.walk(config):
        safe_config = safe_config and not writable(root)
        for filename in files:
            if filename.endswith(('.hcl', '.json')):
                found += 1
                path = os.path.join(root, filename)
                s = os.stat(path)
                safe_config = safe_config and s.st_uid == 0 and not writable(path) and stat.S_IMODE(s.st_mode) & 7 == 0
    record('configuration_files_private_readonly', found > 0 and safe_config)
    for path, name in ([(data, 'raft_directory')] if storage == 'raft' else []) + [(audit, 'audit_directory')]:
        s = os.stat(path)
        record(name + '_private', s.st_uid == account.pw_uid and stat.S_IMODE(s.st_mode) == 0o700 and writable(path))
    with open('/proc/swaps') as f:
        record('no_active_swap', len(f.read().splitlines()) == 1)
    with open('/etc/fstab') as f:
        swap_fstab = any(len(parts) >= 3 and parts[2] == 'swap' for parts in
                         (line.split() for line in f if line.strip() and not line.lstrip().startswith('#')))
    record('no_fstab_swap', not swap_fstab, 'Also review zram/cloud-init and other swap generators.')
    with open('/proc/sys/fs/suid_dumpable') as f:
        record('suid_dumpable_zero', f.read().strip() == '0')
    rc, synced = command(['timedatectl', 'show', '--property=NTPSynchronized', '--value'])
    record('clock_synchronized', rc == 0 and synced == 'yes', synced)
    rc, version = command([binary, 'version'])
    match = re.search(r'v(\d+)\.(\d+)\.(\d+)', version)
    record('approved_version_floor', rc == 0 and match and tuple(map(int, match.groups())) >= tuple(map(int, minimum.split('.'))), version)
    record('rotation_config_installed', os.path.isfile('/etc/logrotate.d/vault-hardening'))
    rc, _ = command(['logrotate', '--debug', '/etc/logrotate.d/vault-hardening'])
    record('rotation_config_valid', rc == 0)
    if require_mac == 'yes':
        selinux = os.path.isfile('/sys/fs/selinux/enforce') and open('/sys/fs/selinux/enforce').read().strip() == '1'
        apparmor = os.path.isfile('/sys/module/apparmor/parameters/enabled') and open('/sys/module/apparmor/parameters/enabled').read().strip() == 'Y'
        record('mandatory_access_control_active', selinux or apparmor, 'Does not attest that a Vault-specific policy is loaded.')
    u = urlsplit(url)
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(u.hostname, u.port or 443, context=context, timeout=10)
    connection.connect()
    record('direct_tls_verified', connection.sock.version() in ('TLSv1.2', 'TLSv1.3'), connection.sock.version())
    connection.request('GET', '/v1/sys/health')
    response = connection.getresponse()
    headers = dict((k.lower(), v) for k, v in response.getheaders())
    health = json.loads(response.read())
    record('direct_node_healthy', response.status in (200, 429, 473) and health.get('initialized') and not health.get('sealed'))
    if require_hsts == 'yes':
        hsts = headers.get('strict-transport-security', '')
        age = re.search(r'max-age=(\d+)', hsts)
        record('hsts_present', age and int(age.group(1)) > 0, hsts)
    connection.close()
except Exception as error:
    record('verification_completed', False, type(error).__name__ + ': ' + str(error))
print(json.dumps({'passed': all(c['passed'] for c in checks), 'checks': checks}))
