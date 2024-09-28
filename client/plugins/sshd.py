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

# Try to identify a running sshd process in two ways: (1) look for a process
# with the name "sshd" or "in.sshd"; (2) look for a process listening on port
# 22. If neither of those is found, then assume that sshd is stopped.
#
# Separately, check the sshd configuration for password-based logins by
# invoking sshd with the "-T" argument to get its effective configuration. If
# we were able to identify a running sshd process as described above, then use
# that process to determine the path to the sshd binary and/or the non-default
# configuration file name. Otherwise, just do "sshd -T", hoping that it'll be
# in our search path.

import json
import psutil
import re
import subprocess

sshd_name_re = re.compile(r'\bsshd\b|\bin\.sshd\b')

results = {}

try:
    sshd_process = None
    for p in psutil.process_iter():
        try:
            if sshd_name_re.search(p.exe()) or \
               any(c for c in p.net_connections('tcp')
                   if c.laddr[1] == 22 and not len(c.raddr)):
                sshd_process = p.as_dict(attrs=('exe', 'cmdline'))
                break
        except (FileNotFoundError, psutil.NoSuchProcess):
            continue
    else:
        raise StopIteration()
except StopIteration:
    sshd_process = None
    results['status'] = 'stopped'
    sshd_config_command = ['sshd', '-T']
else:
    results['status'] = 'running'
    sshd_config_command = [sshd_process['exe'], '-T']
    sshd_cmdline = sshd_process['cmdline']
    try:
        sshd_config_file = sshd_cmdline[sshd_cmdline.index('-f') + 1]
        sshd_config_command.extend(['-f', sshd_config_file])
    except Exception:
        pass

try:
    sshd_config = subprocess.check_output(
        sshd_config_command, stderr=open('/dev/null', 'w')).decode('utf8')
except FileNotFoundError:
    if not sshd_process:
        results['status'] = 'missing'
    sshd_config = ''
except Exception:
    sshd_config = ''

results['config'] = {}
if sshd_config:
    for config in sshd_config.strip().split('\n'):
        key, value = config.split(' ', 1)
        results['config'][key] = value

print(json.dumps(results))
