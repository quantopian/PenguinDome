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

from configparser import ConfigParser
import glob
import os
import re
import subprocess

from penguindome import cached_data
import penguindome.json as json
from penguindome.plugin_tools import (
    find_xinit_users,
    find_x_users,
    process_dict_iter,
)


def xinit_checker():
    return False if find_xinit_users() else None


def lightdm_checker():
    lightdm_re = re.compile(r'\blightdm\b')
    running_lightdm = any(p for p in process_dict_iter(('exe',))
                          if lightdm_re.search(p['exe']))
    if not running_lightdm:
        return None
    if not (os.path.exists('/usr/share/lightdm/guest-session') or
            os.path.exists('/usr/lib/lightdm/lightdm-guest-session')):
        return None
    # "allow-guest" setting in "Seat:*" INI section controls whether guest
    # session is allowed. It defaults to true if not set.
    parser = ConfigParser()
    parser.read(glob.glob('/usr/share/lightdm/lightdm.conf.d/*.conf') +
                glob.glob('/etc/lightdm/*.conf'))
    if not parser.has_section('Seat:*'):
        return True
    if not parser.has_option('Seat:*', 'allow-guest'):
        return True
    try:
        return parser.getboolean('Seat:*', 'allow-guest')
    except ValueError:
        return True


def gdm3_checker():
    # gdm3 doesn't support guest sessions
    running_gdm3 = any(p for p in process_dict_iter(('exe', 'username'))
                       if p['username'] == 'root' and
                       re.search(r'/gdm3$', p['exe']))
    if running_gdm3:
        return False
    # Sometimes the gdm3 binary is just called gdm
    try:
        running_gdm = next(p for p in process_dict_iter(('exe', 'username'))
                           if p['username'] == 'root' and
                           re.search(r'/gdm$', p['exe']))
    except StopIteration:
        return None
    try:
        version = subprocess.check_output((running_gdm['exe'], '--version'),
                                          universal_newlines=True)
    except subprocess.CalledProcessError:
        return None
    # Format looks like "GDM 3.30.2"
    match = re.search(r' (\d+)', version)
    if not match:
        return None
    # We are specifically looking for GDM version 3 here, not newer versions,
    # because it is possible that newer versions will support guest sessions.
    return False if int(match.group(1)) == 3 else None


def xguest_checker():
    # Fedora uses "xguest" RPM, which creates "xguest" user, as its guest
    # session.
    try:
        subprocess.check_call(('dnf', 'info', 'xguest'),
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return any(line for line in open('/etc/passwd')
               if re.match(r'xguest:', line))


def greetd_checker():
    # greetd doesn't support guest sesssions
    running_greetd = any(p for p in process_dict_iter(('exe', 'username'))
                         if p['username'] == 'root' and
                         re.search(r'/greetd$', p['exe']))
    if running_greetd:
        return False


# Make sure xinit_checker is last. Just because somebody is running xinit
# doesn't mean that they aren't _also_ running a display manager that has a
# guest session, so xinit_checker should only be used as a last resort.
checkers = (lightdm_checker, xinit_checker, gdm3_checker, xguest_checker,
            greetd_checker)

for checker in checkers:
    results = checker()
    if results is not None:
        break

if results is None:
    results = 'unknown'

results = ({'enabled': results}
           if results != 'unknown' or find_x_users()
           else None)
results = cached_data('guest_session', results, add_timestamp=True,
                      raise_exception=False)
print(json.dumps(results))
