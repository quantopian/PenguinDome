#!/usr/bin/env python3

import json
import netifaces

results = {}

for device in netifaces.interfaces():
    if device.startswith('lo'):
        continue
    results[device] = netifaces.ifaddresses(device)

print(json.dumps(results))
