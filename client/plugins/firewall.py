#!/usr/bin/env python3

import json
import re
import subprocess

chain_re = re.compile(r'^Chain (.*) \(policy (.*)\)')


def get_policies(cmd):
    try:
        output = subprocess.check_output(
            (cmd, '-L', '-n'), stderr=subprocess.STDOUT).decode('ascii')
    except subprocess.CalledProcessError as e:
        if re.search(r'Module \S+ not found', e.output.decode('ascii')):
            # Not enabled in kernel
            return None
        print(e.output.decode('ascii'))
    lines = output.strip().split('\n')
    chains = filter(None, (chain_re.match(l) for l in lines))
    return {c.group(1): c.group(2)
            for c in chains}


results = {}

results['layers'] = {}
for layer in ('iptables', 'ip6tables'):
    policies = get_policies(layer)
    if policies is None:
        continue
    results['layers'][layer] = {
        'policies': policies,
        'status': ('on'
                   if 'ACCEPT' not in (policies['INPUT'], policies['FORWARD'])
                   else 'off'),
    }

results['status'] = 'off' if any(l for l in results['layers'].values()
                                 if l['status'] == 'off') else 'on'

print(json.dumps(results))
