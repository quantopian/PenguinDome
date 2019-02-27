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

import re
import subprocess
from tempfile import TemporaryFile

from penguindome import cached_data
from penguindome.client import get_logger
import penguindome.json as json
from penguindome.plugin_tools import find_x_users, DBusUser, process_dict_iter

valid_lockers = (
    'betterlockscreen', 'slock', 'i3lock', 'i3lock-fancy', 'i3lock-fancy-rapid'
)
valid_lockers_re = re.compile(r'^(?:' +
                              '|'.join(re.escape(l) for l in valid_lockers) +
                              r')(?:\s|$)')
log = get_logger('plugins/screenlock')


def gnome_xscreensaver_status(user, display):
    try:
        dbus_user = DBusUser(user, display)
    except KeyError:
        return None

    with TemporaryFile('w+') as stderr_file:
        try:
            dbus_output = dbus_user.command(
                'echo $DBUS_SESSION_BUS_ADDRESS; '
                'dbus-send --session --dest=org.freedesktop.DBus '
                '--type=method_call --print-reply /org/freedesktop/Dbus org.'
                'freedesktop.DBus.ListNames',
                stderr=stderr_file)
        except subprocess.CalledProcessError as e:
            stdout = e.output.decode('utf8').strip()
            stderr_file.seek(0)
            stderr = stderr_file.read().strip()
            log.debug('dbus-send failed')
            if stdout:
                log.debug('dbus-send output: {}', stdout)
            if stderr:
                log.debug('dbus-send stderr: {}', stderr)
            if 'Could not parse server address' in stderr:
                log.debug('dbus-send DBUS_SESSION_BUS_ADDRESS={}',
                          dbus_user.environ.get('DBUS_SESSION_BUS_ADDRESS',
                                                None))
            return None
    if dbus_output.find('org.gnome.ScreenSaver') == -1:
        return None

    def gsettings_get(app, setting):
        return dbus_user.command(
            'gsettings get org.gnome.desktop.{} {}'.format(
                app, setting)).strip()

    lock_enabled = gsettings_get('screensaver', 'lock-enabled') == 'true'
    idle_enabled = gsettings_get('screensaver',
                                 'idle-activation-enabled') == 'true'
    lock_delay = int(gsettings_get('screensaver', 'lock-delay').split()[1])
    idle_delay = int(gsettings_get('session', 'idle-delay').split()[1])
    # The screen goes blank after idle_delay and locks after idle_delay +
    # lock_delay
    results = {'enabled': lock_enabled and idle_enabled,
               'delay': idle_delay + lock_delay}
    return results


def xautolock_status(user, display):
    procs = (p for p in process_dict_iter(
        ('username', 'environ', 'exe', 'cmdline')) if p['username'] == user)
    procs = (p for p in procs if p['environ'].get('DISPLAY', None) == display)
    procs = (p for p in procs if p['exe'].endswith('/xautolock'))
    for proc in procs:
        _time = locker = nowlocker = None
        args = proc['cmdline']
        try:
            while args:
                if args[0] == '-time':
                    _time = int(args[1]) * 60
                    del args[0:2]
                elif args[0] == '-locker':
                    locker = args[1]
                    del args[0:2]
                elif args[0] == '-nowlocker':
                    nowlocker = args[1]
                    del args[0:2]
                else:
                    args.pop(0)
                if _time and locker and nowlocker:
                    break
        except:
            continue
        if not nowlocker:
            nowlocker = locker
        if _time and valid_lockers_re.search(locker) and \
           valid_lockers_re.search(nowlocker):
            return {'enabled': True, 'delay': _time}
    return None


def xidlehook_status(user, display):
    procs = (p for p in process_dict_iter(
        ('username', 'environ', 'exe', 'cmdline')) if p['username'] == user)
    procs = (p for p in procs if p['environ'].get('DISPLAY', None) == display)
    procs = (p for p in procs if p['exe'].endswith('/xidlehook'))
    for proc in procs:
        args = proc['cmdline']
        timers = []
        try:
            while args:
                # xidlehook timers always have 4 positional arguments
                # https://github.com/jD91mZM2/xidlehook/blob/cbc3302e3485a8308d6ba5dd6b4d069d322908dd/src/main.rs#L122  # noqa
                if args[0] == '--timer':
                    timers.append({
                        'time': int(args[2]),
                        'locker': args[3]
                    })
                    del args[0:5]
                else:
                    args.pop(0)
        except:
            continue

        # in xidlehook, each subsequent --timer is run after previous timer(s)
        # so the total effective time is cumulative
        total_timers = 0
        for timer in timers:
            total_timers += timer['time']
            if valid_lockers_re.search(timer['locker']):
                return {'enabled': True, 'delay': total_timers}
    return None


display_checkers = (gnome_xscreensaver_status, xautolock_status,
                    xidlehook_status)

user_displays = find_x_users()

results = {}

for user, display in user_displays:
    for checker in display_checkers:
        status = checker(user, display)
        if status:
            status['user'] = user
            results[user] = status
            break
    else:
        results[user] = {'user': user, 'enabled': 'unknown'}

results = {'users': list(results.values())} if user_displays else None
results = cached_data('screenlock', results, add_timestamp=True,
                      raise_exception=False)
print(json.dumps(results))
