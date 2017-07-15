#!/usr/bin/env python

import json
import re
import subprocess

output = subprocess.check_output('dmidecode')

results = {}
results['full'] = output
sections = output.split('\n\n')
want_section = 'System Information'
system_information = next(s for s in sections if s.find(want_section) > -1)
results[want_section] = {}
for field, value in re.findall(r'\n\t\b([^:]+):\s*(.*\S(?:\n\t\t.*\S)*)',
                               system_information):
    if value == 'Not Applicable':
        continue
    results[want_section][field] = value
print json.dumps(results)
