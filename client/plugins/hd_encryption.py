#!/usr/bin/env python3

# Quantopian, Inc. licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import json
import re
import subprocess

from penguindome.client import get_logger

results = {}
log = get_logger('plugins/hd_encryption')


def is_encrypted(device):
    try:
        subprocess.check_output(['cryptsetup', 'status', device])
        return True
    except Exception:
        pass
    try:
        # I hope it's a logical volume!
        vg = subprocess.check_output(
            ('lvs', '--noheadings', '-o', 'vg_name',
             device), close_fds=True).decode('utf8').strip()
    except Exception:
        log.info('Cryptsetup and lvs on {} failed, assuming not encrypted',
                 device)
        return False
    else:
        if vg == '':
            # https://bugs.launchpad.net/ubuntu/+source/lvm2/+bug/1705534
            # *sigh*
            return False
    pv_output = subprocess.check_output(
        ('vgs', '--noheadings', '-o', 'pv_name', vg),
        close_fds=True).decode('utf8').strip()
    pvs = pv_output.split('\n')
    return all(is_encrypted(p) for p in pvs)


for mount in open('/proc/mounts'):
    mount = mount.strip()
    device, mountpoint, fstype, options, freq, passno = mount.split(' ')
    if fstype in ('aufs', 'autofs', 'binfmt_misc', 'bpf', 'cgroup', 'cgroup2',
                  'cifs', 'configfs', 'debugfs', 'devpts', 'devtmpfs',
                  'efivarfs', 'fuse', 'fuse.gvfsd-fuse', 'fusectl',
                  'hugetlbfs', 'iso9660', 'mqueue', 'nfs', 'nsfs', 'overlay',
                  'proc',
                  'pstore', 'ramfs', 'rpc_pipefs', 'securityfs', 'selinuxfs',
                  'squashfs', 'sysfs',
                  'tmpfs', 'tracefs', 'vboxsf'):
        continue
    if any(True for r in results.values() if r['device'] == device):
        # Bind mounting, probably.
        # Don't need to check the same device twice.
        continue
    if fstype.startswith('fuse'):
        continue
    if fstype == 'ecryptfs':
        results[mountpoint] = {'mountpoint': mountpoint,
                               'device': device,
                               'encrypted': True}
        continue
    if mountpoint in ('/boot', '/boot/efi', '/efi'):
        continue
    if device.find(':') > -1 or device.startswith('//'):
        # Remote device
        continue
    if re.match(r'(?:/run)?/media/', mountpoint):
        # We don't enforce encryption of removable devices with MDM.
        continue

    results[mountpoint] = {'mountpoint': mountpoint,
                           'device': device,
                           'type': fstype,
                           'encrypted': is_encrypted(device)}

print(json.dumps(list(results[k] for k in sorted(results.keys()))))
