#!/usr/bin/env python3

import psutil
import re
import subprocess

from qlmdm import cached_data
from qlmdm.client import get_logger
import qlmdm.json as json

log = get_logger('plugins/screenlock')


def find_xinit_users():
    xinits = []
    for p in psutil.process_iter():
        if p.exe().endswith('/xinit'):
            xinits.append(p)
    if not xinits:
        return ()
    Xorgs = []
    for p in psutil.process_iter():
        if p.exe().endswith('/Xorg'):
            xinit = any(x for x in xinits if p.ppid() == x.pid)
            if xinit:
                Xorgs.append((xinit, p))
    if not Xorgs:
        return ()
    users = []
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


def gnome_xscreensaver_status(user, display):
    def user_command(cmd):
        return subprocess.check_output(('su', user, '-c', cmd),
                                       env=environ).decode('ascii')

    # Find out the user's dbus settings.
    for proc in psutil.process_iter():
        if proc.username() != user:
            continue
        environ = proc.environ()
        if environ.get('DISPLAY', None) != display:
            continue
        if 'DBUS_SESSION_BUS_ADDRESS' not in environ:
            continue

        dbus_output = user_command(
            'dbus-send --session --dest=org.freedesktop.DBus '
            '--type=method_call --print-reply /org/freedesktop/Dbus '
            'org.freedesktop.DBus.ListNames')
        if dbus_output.find('org.gnome.ScreenSaver') == -1:
            continue
        break
    else:
        return None

    def gsettings_get(app, setting):
        return user_command(
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


display_checkers = (gnome_xscreensaver_status,)

# Who is logged into an X display?

w_lines = subprocess.check_output(
    ('who',)).decode('ascii').strip().split('\n')
matches = (re.match(r'(\S+)\s+.*\((:\d[^\)]*)\)', l) for l in w_lines)
matches = filter(None, matches)
user_displays = [m.groups() for m in matches]

if not user_displays:
    user_displays = find_xinit_users()

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
