#!/usr/bin/env python3

import psutil
import re
import subprocess

from qlmdm import cached_data
from qlmdm.client import get_logger
import qlmdm.json as json

log = get_logger('plugins/screenlock')


def find_xinit_users():
    users = []
    xinits = []
    for p in psutil.process_iter():
        if p.exe().endswith('/xinit'):
            xinits.append(p)
    if not xinits:
        return users
    Xorgs = []
    for p in psutil.process_iter():
        if p.exe().endswith('/Xorg'):
            xinit = any(x for x in xinits if p.ppid() == x.pid)
            if xinit:
                Xorgs.append((xinit, p))
    if not Xorgs:
        return users
    for xinit, Xorg in Xorgs:
        try:
            display = next(a for a in Xorg.cmdline() if a[0] == ':')
        except:
            continue
        try:
            proc = min((p for p in psutil.process_iter() if 'DISPLAY' in
                        p.environ() and p.environ()['DISPLAY'] == display),
                       key=lambda p: p.pid)
        except:
            continue
        users.append((proc.username(), display))
    return users


class DBusUser(object):
    found_users = {}

    def __init__(self, user, display):
        # Find out the user's dbus settings.
        self.user = user
        self.display = display
        which = (user, display)
        try:
            self.environ = self.found_users[which]
            return
        except KeyError:
            pass
        for proc in psutil.process_iter():
            if proc.username() != user:
                continue
            environ = proc.environ()
            if environ.get('DISPLAY', None) != display:
                continue
            if 'DBUS_SESSION_BUS_ADDRESS' not in environ:
                continue
            self.found_users[which] = environ
            break
        self.environ = self.found_users[which]

    def __str__(self):
        return("<DBusUser('{}', '{}')>".format(self.user, self.display))

    def command(self, cmd):
        return subprocess.check_output(('su', self.user, '-c', cmd),
                                       env=self.environ).decode('ascii')


def gnome_xscreensaver_status(user, display):
    try:
        dbus_user = DBusUser(user, display)
    except KeyError:
        return None

    dbus_output = dbus_user.command(
        'dbus-send --session --dest=org.freedesktop.DBus --type=method_call '
        '--print-reply /org/freedesktop/Dbus org.freedesktop.DBus.ListNames')
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
        if _time and locker == 'slock' and nowlocker == 'slock':
            return {'enabled': True, 'delay': _time}
    return None


display_checkers = (gnome_xscreensaver_status, xautolock_status)

# Who is logged into an X display?

w_lines = subprocess.check_output(
    ('who',)).decode('ascii').strip().split('\n')
matches = (re.match(r'(\S+)\s+.*\((:\d[^\)]*)\)', l) for l in w_lines)
matches = filter(None, matches)
user_displays = [m.groups() for m in matches] + find_xinit_users()

results = {}

if not user_displays:
    log.warn('Failed to identify any X users')
else:
    for user, display in user_displays:
        for checker in display_checkers:
            status = checker(user, display)
            if status:
                status['user'] = user
                results[user] = status
                break
        else:
            results[user] = {'user': user, 'enabled': 'unknown'}

results = {'users': list(results.values())}
results = cached_data('screenlock', results, add_timestamp=True,
                      check_logged_in=True)
print(json.dumps(results))
