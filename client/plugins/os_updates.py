#!/usr/bin/env python3

import json
import os
import subprocess
from tempfile import TemporaryFile
import time

from qlmdm.client import get_logger

log = get_logger('plugins/os_updates')


def arch_checker():
    def status(current, updates):
        try:
            output = subprocess.check_output(('pacman', '-Q'),
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            if updates != 'unknown':  # i.e., pacman didn't already fail
                log.error('Call to pacman -Q failed. Output: {}',
                          e.output.decode('ascii'))
            installed = []
        else:
            installed = [l.split(' ')[0]
                         for l in output.decode('ascii').strip().split('\n')]

        return {'current': current,
                'release': False,
                'patches': updates,
                'security_patches': 'unknown',
                'installed_packages': installed}

    try:
        subprocess.check_output(('pacman', '-Sy'), stderr=subprocess.STDOUT)
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError as e:
        log.error('Call to pacman -Sy failed. Output: {}',
                  e.output.decode('ascii'))
        return status(False, 'unknown')

    try:
        subprocess.check_output(
            ('pacman', '-Qu'), stderr=subprocess.STDOUT).decode('ascii')
    except subprocess.CalledProcessError as e:
        if e.returncode == 1 and not e.output:
            return status(True, False)
        log.error('Call to pacman -Qu failed. Output: {}',
                  e.output.decode('ascii'))
        return status(True, 'unknown')

    return status(True, True)


def ubuntu_checker():
    results = {}

    with TemporaryFile() as f:
        try:
            subprocess.check_output(('do-release-upgrade', '-c'), stderr=f)
            results['release'] = True
        except OSError:
            return None
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                # If there was stderr, then something is wrong.
                results['release'] = ('unknown'
                                      if os.fstat(f.fileno()).st_size > 0
                                      else False)
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
        output = subprocess.check_output(
            '/usr/lib/update-notifier/apt-check',
            stderr=subprocess.STDOUT).decode('ascii')
    except OSError:
        results['patches'] = 'unknown'
    else:
        update_counts = tuple(int(c) for c in output.strip().split(';'))
        results['patches'] = update_counts[0] > 0
        results['security_patches'] = update_counts[1] > 0
    return results


checkers = (ubuntu_checker, arch_checker)

for checker in checkers:
    results = checker()
    if results is not None:
        break

if results is None:
    results = 'unknown'

print(json.dumps(results))
