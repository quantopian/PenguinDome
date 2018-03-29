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
import requests

results = {}

try:
    response = requests.get('https://v4.ident.me', timeout=30)
    response.raise_for_status()
    results['public_ipv4'] = response.content.decode('utf8')
except:
    results['public_ipv4'] = 'unknown'

try:
    response = requests.get('https://v6.ident.me', timeout=30)
    response.raise_for_status()
    results['public_ipv6'] = response.content.decode('utf8')
except:
    results['public_ipv6'] = 'unknown'

print(json.dumps(results))
