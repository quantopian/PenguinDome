#!/usr/bin/env python

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

try:
    sshd_process = next(p for p in psutil.process_iter()
                        if sshd_name_re.search(p.exe()) or
                        any(c for c in p.connections('tcp')
                            if c.laddr[1] == 22 and not len(c.raddr)))
    sshd_config_command = [sshd_process.exe(), '-T']
    sshd_cmdline = sshd_process.cmdline()
    try:
        sshd_config_file = sshd_cmdline[sshd_cmdline.index('-f') + 1]
        sshd_config_command.extend(['-f', sshd_config_file])
    except:
        pass
except:
    sshd_process = None
    sshd_config_command = ['sshd', '-T']

try:
    sshd_config = subprocess.check_output(sshd_config_command)
except:
    sshd_config = ''

results = {}

if sshd_process:
    results['status'] = 'running'
elif sshd_config:
    results['status'] = 'stopped'
else:
    results['status'] = 'missing'

results['config'] = {}
for config in sshd_config.strip().split('\n'):
    key, value = config.split(' ', 1)
    results['config'][key] = value

print json.dumps(results)
