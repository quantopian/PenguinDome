#!/usr/bin/env python

import cPickle as pickle
import json
import os
import re
import requests
import subprocess
import sys

from qlmdm import top_dir, var_dir, get_client_settings

cache_file = os.path.join(var_dir, 'geolocation.cache')

os.chdir(top_dir)


def unknown():
    print(json.dumps('unknown'))
    sys.exit()


def old_data_is_good(old_data, ip_addresses, access_points):
    if 'response' not in old_data:
        return False

    try:
        old_ip_addresses = set(old_data['ip_addresses'].values())
    except:
        old_ip_addresses = set()
    new_ip_addresses = set(ip_addresses.values())
    if old_ip_addresses != new_ip_addresses:
        return False

    new_mac_addresses = set(a['macAddress'] for a in access_points)
    if not new_mac_addresses:
        return True

    try:
        old_mac_addresses = set(a['macAddress']
                                for a in old_data['access_points'])
    except:
        old_mac_addresses = set()

    percentage_overlap = (100 * len(new_mac_addresses & old_mac_addresses) /
                          len(new_mac_addresses))
    if percentage_overlap > 74:
        return True

    return False


client_settings = get_client_settings()
try:
    api_key = client_settings['geolocation_api_key']
except:
    unknown()

address_re = re.compile(
    r'\bAddress:\s*([0-9a-f][0-9a-f](?::[0-9a-f][0-9a-f])*)',
    re.IGNORECASE)
signal_re = re.compile(r'\bSignal level=(-\d+)\d*dBm')
channel_re = re.compile(r'\bChannel:\s*(\d+)')

access_points = {}

ip_addresses = json.loads(
    subprocess.check_output('client/plugins/ip_addresses.py'))

try:
    old_data = pickle.load(open(cache_file))
except:
    old_data = {}

# iwlist returns slightly different results every time, so we need to run it
# several times and merge the output.
for i in range(5):
    try:
        output = subprocess.check_output(('iwlist', 'scan'),
                                         stderr=subprocess.STDOUT)
    except:
        unknown()

    for cell in re.split(r'\n\s+Cell \d+ ', output):
        ap = {}
        match = address_re.search(cell)
        if not match:
            continue
        ap['macAddress'] = match.group(1).lower()

        match = signal_re.search(cell)
        if match:
            ap['signalStrength'] = match.group(1)

        match = channel_re.search(cell)
        if match:
            ap['channel'] = match.group(1)

        access_points[ap['macAddress']] = ap

    # To conserve API quota, don't submit if WiFi access points match the last
    # call's 75% or more and the IP addresses haven't changed.
    if old_data_is_good(old_data, ip_addresses, access_points.values()):
        sys.stderr.write('Using old data\n')
        print(json.dumps(old_data['response']))
        sys.exit()

data = {}
if access_points:
    data['wifiAccessPoints'] = access_points.values()

url = 'https://www.googleapis.com/geolocation/v1/geolocate?key={}'.format(
    api_key)
response = requests.post(url, data=json.dumps(data))
try:
    response.raise_for_status()
except:
    unknown()

old_data = {
    'response': response.json(),
    'ip_addresses': ip_addresses,
    'access_points': access_points,
}

pickle.dump(old_data, open(cache_file, 'w'))

print(json.dumps(response.json()))
