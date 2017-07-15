#!/usr/bin/env python

import json
import netinfo

results = {}

for device in netinfo.list_active_devs():
    if device == 'lo':
        continue
    results[device] = {}
    address = netinfo.get_ip(device)
    if address.startswith('127.'):
        continue
    results[device]['ip'] = address

print(json.dumps(results))
