#!/usr/bin/env python

import json
import subprocess

results = {}

try:
    subprocess.check_output(('systemctl', 'show', 'prey-agent'))
    results['running'] = True
except:
    results['running'] = False

print(json.dumps(results))
