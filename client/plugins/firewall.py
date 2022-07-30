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

chain_re = re.compile(r'^Chain (.*) \(policy (.*)\)')


def get_policies(cmd):
    try:
        output = subprocess.check_output(
            (cmd, '-L', '-n'), stderr=subprocess.STDOUT).decode('utf8')
    except subprocess.CalledProcessError as e:
        if re.search(r'Module \S+ not found', e.output.decode('utf8')):
            # Not enabled in kernel
            return None
        print(e.output.decode('utf8'))
    lines = output.strip().split('\n')
    chains = filter(None, (chain_re.match(line) for line in lines))
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

results['status'] = 'off' if any(layer for layer in results['layers'].values()
                                 if layer['status'] == 'off') else 'on'

print(json.dumps(results))
