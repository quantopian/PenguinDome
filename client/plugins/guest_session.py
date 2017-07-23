#!/usr/bin/env python3

from configparser import SafeConfigParser
import glob
import json
import os
import psutil
import re


def xinit_checker():
    xinit = Xorg = None
    for p in psutil.process_iter():
        if p.exe().endswith('/xinit'):
            xinit = p
        elif p.exe().endswith('/Xorg'):
            Xorg = p
    if xinit and Xorg and Xorg.ppid() == xinit.pid and \
       xinit.uids().real and Xorg.uids().real:  # Shouldn't be running as root
        return False

    return None


def lightdm_checker():
    lightdm_re = re.compile(r'\blightdm\b')
    running_lightdm = any(p for p in psutil.process_iter()
                          if lightdm_re.search(p.exe()))
    if not running_lightdm:
        return None
    if not os.path.exists('/usr/share/lightdm/guest-session'):
        return None
    if not os.path.exists('/usr/share/lightdm/lightdm.conf.d'):
        return None
    status = None
    for conf_file in glob.glob('/usr/share/lightdm/lightdm.conf.d/*.conf'):
        parser = SafeConfigParser()
        parser.read(conf_file)
        if not parser.has_section('Seat:*'):
            continue
        if not parser.has_option('Seat:*', 'allow-guest'):
            continue
        if parser.getboolean('Seat:*', 'allow-guest'):
            return True
        status = False
    return status


# Make sure xinit_checker is last. Just because somebody is running xinit
# doesn't mean that they aren't _also_ running a display manager that has a
# guest session, so xinit_checker should only be used as a last resort.
checkers = (lightdm_checker, xinit_checker)

for checker in checkers:
    results = checker()
    if results is not None:
        break

if results is None:
    results = 'unknown'

print(json.dumps({'enabled': results}))
