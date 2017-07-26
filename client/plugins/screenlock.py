#!/usr/bin/env python3

import psutil
import re
import subprocess
from tempfile import TemporaryFile

from qlmdm import cached_data
from qlmdm.client import get_logger
import qlmdm.json as json
from qlmdm.plugin_tools import find_x_users, DBusUser

valid_lockers = ('slock', 'i3lock')
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
                'echo $FOOBAR $DBUS_SESSION_BUS_ADDRESS; '
                'dbus-send --session --dest=org.freedesktop.DBus '
                '--type=method_call --print-reply /org/freedesktop/Dbus org.'
                'freedesktop.DBus.ListNames',
                stderr=stderr_file)
        except subprocess.CalledProcessError as e:
            stdout = e.output.decode('ascii').strip()
            stderr_file.seek(0)
            stderr = stderr_file.read().strip()
            log.error('dbus-send failed')
            if stdout:
                log.error('dbus-send output: {}', stdout)
            if stderr:
                log.error('dbus-send stderr: {}', stderr)
            if 'Could not parse server address' in stderr:
                log.error('dbus-send DBUS_SESSION_BUS_ADDRESS={}',
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
    procs = (p for p in psutil.process_iter()
             if p.username() == user)
    procs = (p for p in procs if p.environ().get('DISPLAY', None) == display)
    procs = (p for p in procs if p.exe().endswith('/xautolock'))
    for proc in procs:
        _time = locker = nowlocker = None
        args = proc.cmdline()
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


display_checkers = (gnome_xscreensaver_status, xautolock_status)

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
