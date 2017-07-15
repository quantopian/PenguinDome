#!/usr/bin/env python

import json
import os
import subprocess
import time


def ubuntu_checker():
    results = {}

    try:
        output = subprocess.check_output(('do-release-upgrade', '-c'))
        results['release'] = True
    except OSError:
        return None
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            results['release'] = False
        else:
            results['release'] = 'unknown'

    try:
        update_stamp = os.stat(
            '/var/lib/apt/periodic/update-success-stamp').st_mtime
        results['current'] = time.time() - update_stamp < 60 * 60 * 24 * 2
    except:
        results['current'] = False

    try:
        # So annoying and wrong that output goes to stderr!
        output = subprocess.check_output('/usr/lib/update-notifier/apt-check',
                                         stderr=subprocess.STDOUT)
    except OSError:
        results['patches'] = 'unknown'
    else:
        update_counts = tuple(int(c) for c in output.strip().split(';'))
        results['patches'] = update_counts[0] > 0
        results['security_patches'] = update_counts[1] > 0
    return results


checkers = (ubuntu_checker,)

for checker in checkers:
    results = checker()
    if results is not None:
        break

if results is None:
    results = 'unknown'

print json.dumps(results)
