#!/usr/bin/env python3

import json
import psutil
import subprocess


def gnome_xscreensaver_status(user, display):
    def user_command(cmd):
        return subprocess.check_output(('su', user, '-c', cmd)).decode('ascii')

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
    ('w', '-h', '-s')).decode('ascii').strip().split('\n')
w_tuples = (l.split() for l in w_lines)
w_xlogins = (t for t in w_tuples if t[2].startswith(':'))
user_displays = ((t[0], t[2]) for t in w_xlogins)

results = {}

for user, display in user_displays:
    for checker in display_checkers:
        status = checker(user, display)
        status['user'] = user
        if status:
            results[user] = status
            break
    else:
        results[user] = {'user': user, 'enabled': 'unknown'}

print(json.dumps(list(results.values())))
