#!/usr/bin/env python3

import json
import requests

results = {}

try:
    response = requests.get('https://v4.ident.me', timeout=30)
    response.raise_for_status()
    results['public_ipv4'] = response.content.decode('ascii')
except:
    results['public_ipv4'] = 'unknown'

try:
    response = requests.get('https://v6.ident.me', timeout=30)
    response.raise_for_status()
    results['public_ipv6'] = response.content.decode('ascii')
except:
    results['public_ipv6'] = 'unknown'

print(json.dumps(results))
