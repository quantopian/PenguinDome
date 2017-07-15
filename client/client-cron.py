#!/usr/bin/env python

import datetime
import os
import subprocess
import time

from qlmdm import get_client_settings, top_dir, var_dir, get_logger


def bin_path(cmd):
    return os.path.join(top_dir, 'bin', cmd)


def check_stamp(path, interval):
    try:
        modified = os.stat(path).st_mtime
    except:
        return True
    return time.time() - modified > (interval - 1) * 60


def update_stamp(path):
    open(path, 'w').write(str(datetime.datetime.utcnow()))


os.chdir(top_dir)
client_settings = get_client_settings()
log = get_logger(client_settings, 'client-cron')

try:
    collect_interval = client_settings['schedule']['collect_interval']
except:
    collect_interval = 5

try:
    submit_interval = client_settings['schedule']['submit_interval']
except:
    submit_interval = 1

collect_stamp_file = os.path.join(var_dir, 'collect-stamp')
submit_stamp_file = os.path.join(var_dir, 'submit-stamp')

# This is called once per minute, so we're going to round up.

do_collect = check_stamp(collect_stamp_file, collect_interval)
do_submit = do_collect or check_stamp(submit_stamp_file, submit_interval)

try:
    subprocess.check_output((bin_path('update'),), stderr=subprocess.STDOUT)
except subprocess.CalledProcessError as e:
    log.error('update failed:\n{}', e.output)

subprocess.check_output((bin_path('verify'),))

if do_collect:
    try:
        subprocess.check_output((bin_path('collect'), '--plugins'),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('collect --plugins failed:\n{}', e.output)

if do_submit:
    try:
        subprocess.check_output((bin_path('submit'),),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('submit failed:\n{}', e.output)
    else:
        update_stamp(submit_stamp_file)

if do_collect:
    try:
        subprocess.check_output((bin_path('collect'), '--commands'),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('collect --commands failed:\n{}', e.output)

    # We don't want to hose the machine, so even when collectin fails, we still
    # wait for the configured interval.
    update_stamp(collect_stamp_file)

    try:
        subprocess.check_output((bin_path('submit'),),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('submit failed:\n{}', e.output)
    else:
        update_stamp(submit_stamp_file)
