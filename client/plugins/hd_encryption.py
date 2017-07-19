#!/usr/bin/env python3

import json
import subprocess

results = {}


def is_encrypted(device):
    try:
        subprocess.check_output(['cryptsetup', 'status', device])
        return True
    except:
        pass
    # I hope it's a logical volume!
    vg = subprocess.check_output(
        ('lvs', '--noheadings', '-o', 'vg_name',
         device), close_fds=True).decode('ascii').strip()
    pv_output = subprocess.check_output(
        ('vgs', '--noheadings', '-o', 'pv_name', vg),
        close_fds=True).decode('ascii').strip()
    pvs = pv_output.split('\n')
    return all(is_encrypted(p) for p in pvs)


for mount in open('/proc/mounts'):
    mount = mount.strip()
    device, mountpoint, type, options, freq, passno = mount.split(' ')
    if type in ('autofs', 'binfmt_misc', 'cgroup', 'debugfs', 'devpts',
                'devtmpfs', 'hugetlbfs', 'mqueue', 'nfs', 'proc', 'pstore',
                'rpc_pipefs', 'securityfs', 'sysfs', 'tmpfs', 'tracefs',
                'cgroup2', 'configfs', 'vboxsf'):
        continue
    if type.startswith('fuse'):
        continue
    if mountpoint == '/boot':
        continue
    if device.find(':') > -1:
        # Remove device
        continue
    results[mountpoint] = {'mountpoint': mountpoint,
                           'device': device,
                           'encrypted': is_encrypted(device)}

print(json.dumps(list(results.values())))
