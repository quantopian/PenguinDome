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

# Checkers in this file should return a dict with five keys in it:
#
# "release" -- True or False to indicate whether there is a new OS
#   release available
# "current" -- True or False to indicate whether the metadata on the
#   machine related to updates is current
# "patches" -- True or False to indicate whether there are OS updates
#   of any sort available
# "security_patches" -- True or False to indicate whether there are
#    OS security updates available
# "installed_packages" -- List of installed packages
#
# Any of the booleans can also return the string "unknown".

import json
import os
from psutil import Process
import subprocess
from signal import SIGHUP
from tempfile import TemporaryFile
import time

from penguindome.client import get_logger
from penguindome.plugin_tools import process_dict_iter

log = get_logger('plugins/os_updates')


def arch_checker():
    def ancestors(p, attrs=None):
        if attrs:
            attrs = list(attrs)
            if 'ppid' not in attrs:
                attrs.append('ppid')
        else:
            attrs = ['ppid']

        ancestors = []
        try:
            while p['ppid']:
                p = Process(p['ppid']).as_dict(attrs=attrs)
                ancestors.append(p)
        except FileNotFoundError:
            pass
        return ancestors

    def clear_eset_lock():
        # Identify pacman processes that are descendants of ERAAgent and
        # kill them if they have been running for more than 60 seconds.
        procs = process_dict_iter(('cmdline', 'create_time', 'pid', 'ppid'))
        # All pacman processes
        procs = (p for p in procs
                 if p['cmdline'] and p['cmdline'][0] == 'pacman')
        # Pacman processes with the command-line options that ERAAgent uses
        procs = (p for p in procs
                 if len(p['cmdline']) > 1 and p['cmdline'][1] in
                 ('-Syq', '--version', '--Quq'))
        # Pacman processes which are descendants of ERAAgent
        eraagent_cmd = '/opt/eset/RemoteAdministrator/Agent/ERAAgent'
        procs = (p for p in procs
                 if any(a['cmdline'] and a['cmdline'][0] == eraagent_cmd
                        for a in ancestors(p, ('cmdline',))))
        # Pacman processes which were launched more than 60 seconds ago
        procs = [p for p in procs if time.time() - p['create_time'] > 60]
        if procs:
            log.info('Killing stale ERAAgent pacman process(es): {}',
                     ', '.join('{} (PID {})'.format(
                         ' '.join(p['cmdline']), p['pid']) for p in procs))
            for p in procs:
                os.kill(p['pid'], SIGHUP)

    def clear_lock():
        """Break stale pacman lock file

        Stat file to get inode number, check if it is in use, stat again to
        make sure the inode number is the same. If so and no one is using the
        file, then remove it.

        Returns True if the script should proceed, which means one of three
        things: (1) there was no lock; (2) the lock was removed successfully;
        (3) the lock is more than ten minutes old, in which case what we're
        about to do is probably going to fail, but we should try it anyway and
        let the failure get logged so people will find out about the
        ten-minute-old lock file and do something about it.
        """
        lock_path = '/var/lib/pacman/db.lck'

        try:
            before = os.stat(lock_path).st_ino
        except FileNotFoundError:
            log.debug('clear_lock: not found before')
            return True
        log.debug('clear_lock: found before')

        try:
            subprocess.check_output(('fuser', lock_path),
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            # No one is using the file, so proceed with unlocking if the inode
            # matches.
            log.debug('clear_lock: fuser says not in use')
            pass
        else:
            log.debug('clear_lock: fuser says in use')
            return False

        try:
            after = os.stat(lock_path).st_ino
        except FileNotFoundError:
            # Oh, good, it's gone now!
            log.debug('clear_lock: lock cleared after')
            return True

        if before == after:
            try:
                os.unlink(lock_path)
            except FileNotFoundError:
                # Yet another race condition.
                log.debug('clear_lock: Deleted out from under us')
                return True
            log.warn('Cleared stale lock file {}', lock_path)
            return True

        log.debug('clear_lock: inode changed')
        return False

    def status(current, updates):
        try:
            output = subprocess.check_output(('pacman', '-Q'),
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            if updates != 'unknown':  # i.e., pacman didn't already fail
                log.error('Call to pacman -Q failed. Output: {}',
                          e.output.decode('utf8'))
            installed = []
        else:
            installed = [l.split(' ')[0]
                         for l in output.decode('utf8').strip().split('\n')]

        return {'current': current,
                'release': False,
                'patches': updates,
                'security_patches': 'unknown',
                'installed_packages': installed}

    clear_eset_lock()
    if not clear_lock():
        log.info('Pacman is locked. Giving up for now.')
        return status(False, 'unknown')

    try:
        subprocess.check_output(('pacman', '-Sy'), stderr=subprocess.STDOUT)
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError as e:
        log.error('Call to pacman -Sy failed. Output: {}',
                  e.output.decode('utf8'))
        return status(False, 'unknown')

    try:
        subprocess.check_output(
            ('pacman', '-Qu'), stderr=subprocess.STDOUT).decode('utf8')
    except subprocess.CalledProcessError as e:
        if e.returncode == 1 and not e.output:
            return status(True, False)
        log.error('Call to pacman -Qu failed. Output: {}',
                  e.output.decode('utf8'))
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
            stderr=subprocess.STDOUT).decode('utf8')
    except OSError:
        results['patches'] = 'unknown'
    else:
        update_counts = tuple(int(c) for c in output.strip().split(';'))
        results['patches'] = update_counts[0] > 0
        results['security_patches'] = update_counts[1] > 0
    return results


def fedora_checker():
    if not os.path.exists('/etc/fedora-release'):
        return None
    results = {}

    # I can't figure out how to check on Fedora if there is an OS upgrade
    # available. I've posted about this on Ask Fedora at
    # https://ask.fedoraproject.org/en/question/130124/how-do-i-detect-from-
    # the-command-line-that-a-new-fedora-release-is-available/.
    # Until there's an answer, we'll use return "unknown" for OS upgrades.
    results['release'] = 'unknown'

    # The timestamp of /var/cache/dnf/last_makecache tells us when the DNF
    # metadata were last updated.
    try:
        update_stamp = os.stat('/var/cache/dnf/last_makecache').st_mtime
        results['current'] = time.time() - update_stamp < 60 * 60 * 24 * 2
    except:
        results['current'] = False

    # run dnf -q updateinfo --updates to find out if there are any OS updates
    # available. Non-zero exit status means unknown. Zero exit status but no
    # output means no updates available. Zero exit status with output means
    # updates available.
    try:
        output = subprocess.check_output(
            ('dnf', '-q', 'updateinfo', '--updates'),
            stderr=subprocess.STDOUT).decode('utf8')
    except (OSError, subprocess.CalledProcessError):
        results['patches'] = 'unknown'
    else:
        results['patches'] = len(output) > 0

    # Run dnf -q updateinfo --updates sec to find out if there are any OS
    # security updates available. Same interpretation of results as above.
    try:
        output = subprocess.check_output(
            ('dnf', '-q', 'updateinfo', '--updates', 'sec'),
            stderr=subprocess.STDOUT).decode('utf8')
    except (OSError, subprocess.CalledProcessError):
        results['security_patches'] = 'unknown'
    else:
        results['security_patches'] = len(output) > 0

    try:
        output = subprocess.check_output(
            ('rpm', '-qa'),
            stderr=subprocess.STDOUT).decode('utf8')
    except (OSError, subprocess.CalledProcessError):
        results['installed_packages'] = []
    else:
        # Sorted so that changes will be more obvious.
        results['installed_packages'] = sorted(output.split('\n'))

    return results


checkers = (ubuntu_checker, arch_checker, fedora_checker)

for checker in checkers:
    log.debug('Trying {}'.format(checker))
    results = checker()
    if results is not None:
        break

if results is None:
    results = 'unknown'

print(json.dumps(results))
