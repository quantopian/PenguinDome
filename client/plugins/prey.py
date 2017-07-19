#!/usr/bin/env python3

import json
import subprocess

results = {}

output = subprocess.check_output(
    ('systemctl', 'show', '--property=SubState', 'prey-agent')).decode('ascii')
results['running'] = 'running' in output

print(json.dumps(results))
