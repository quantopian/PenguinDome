#!/usr/bin/env python3

import datetime
import glob
import os
import subprocess
import time

from qlmdm import (
    top_dir,
    var_dir,
    collected_dir,
)
from qlmdm.client import get_setting, get_logger


def bin_path(cmd):
    return os.path.join(top_dir, 'bin', cmd)


def check_stamp(path, interval):
    try:
        modified = os.stat(path).st_mtime
    except:
        return True
    # This is called once per minute, so we're going to round up.
    return time.time() - modified > (interval - 1) * 60


def update_stamp(path):
    open(path, 'w').write(str(datetime.datetime.utcnow()))


os.chdir(top_dir)
log = get_logger('client-cron')

collect_interval = get_setting('schedule:collect_interval')
submit_interval = get_setting('schedule:submit_interval')

collect_stamp_file = os.path.join(var_dir, 'collect-stamp')
submit_stamp_file = os.path.join(var_dir, 'submit-stamp')

do_collect = check_stamp(collect_stamp_file, collect_interval)
do_submit = do_collect or (check_stamp(submit_stamp_file, submit_interval) and
                           glob.glob(os.path.join(collected_dir, '*')))

successful_update = False
try:
    subprocess.check_output((bin_path('update'),),
                            stderr=subprocess.STDOUT)
except subprocess.CalledProcessError as e:
    if e.returncode == 42:
        successful_update = do_collect = do_submit = True
    else:
        log.error('update failed:\n{}', e.output.decode('ascii'))

if not successful_update:
    subprocess.check_output((bin_path('verify'),))

if do_collect:
    try:
        subprocess.check_output((bin_path('collect'), '--plugins'),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('collect --plugins failed:\n{}', e.output.decode('ascii'))

if do_submit:
    try:
        subprocess.check_output((bin_path('submit'),),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('submit failed:\n{}', e.output.decode('ascii'))
    else:
        update_stamp(submit_stamp_file)

if do_collect:
    try:
        subprocess.check_output((bin_path('collect'), '--commands'),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('collect --commands failed:\n{}', e.output.decode('ascii'))

    # We don't want to hose the machine, so even when collectin fails, we still
    # wait for the configured interval.
    update_stamp(collect_stamp_file)

    try:
        subprocess.check_output((bin_path('submit'),),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error('submit failed:\n{}', e.output.decode('ascii'))
    else:
        update_stamp(submit_stamp_file)
