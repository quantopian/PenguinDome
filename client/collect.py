#!/usr/bin/env python

# There's no error-handling here. If anything fails, the whole script will
# fail. In the short term, at least, that's acceptable. If something fails,
# we'll log into the box, look at the exception, figure out why it's failing,
# and fix it. This isn't code we're going to ship, it's code for internal use
# only on machines to which we have full access and can debug as needed.

import argparse
import datetime
import json
import os
import re
import subprocess
import socket
import stat
from tempfile import NamedTemporaryFile
import time

from qlmdm import get_client_settings, top_dir, collected_dir, get_logger
os.chdir(top_dir)

# Some commands the plugins use are in /sbin or /usr/sbin on some
# distributions, and it isn't always in the search path used by cron scripts.
for d in ('/sbin', '/usr/sbin'):
    if d not in os.environ['PATH'].split(':'):
        os.environ['PATH'] += ':' + d

log = get_logger(get_client_settings(), 'collect')


def run_dir(dir_name, parse_output=True, delete_after_success=False,
            submit_failures=False):
    dir_path = os.path.join('client', dir_name)
    results = {}
    if not os.path.exists(dir_path):
        log.debug('Skipping nonexistent directory {}', dir_path)
        return
    for run_file in os.listdir(dir_path):
        run_path = os.path.join(dir_path, run_file)
        if run_file.endswith('~'):
            log.debug('Skipping {}', run_path)
            continue
        if run_file.startswith('.'):
            log.debug('Skipping {}', run_path)
            continue
        run_name = re.sub(r'\.[^.]+$', '', run_file)
        if run_name in results:
            log.error('Skipping file with duplicate name {}',
                      run_path)
            continue
        run_stat = os.stat(run_path)
        run_mode = run_stat.st_mode
        if not stat.S_ISREG(run_mode):
            log.debug('Skipping non-file {}', run_path)
            continue
        if not os.access(run_path, os.X_OK):
            log.debug('Skipping non-executable {}', run_path)
            continue
        log.debug('Running {}', run_path)
        with NamedTemporaryFile() as stderr_file:
            try:
                run_output = subprocess.check_output(
                    run_path,
                    stderr=stderr_file.fileno())
            except subprocess.CalledProcessError as e:
                log.exception('Failed to execute {}', run_path)
                log.debug('Output of failed script:\n{}', e.output)
                if submit_failures:
                    stderr_file.seek(0)
                    results[run_name] = {
                        'stdout': e.output,
                        'stderr': stderr_file.read(),
                        'returncode': e.returncode,
                    }
                else:
                    continue
            else:
                if parse_output:
                    try:
                        results[run_name] = json.loads(run_output)
                    except:
                        log.exception('Output of {} failed to parse', run_path)
                        continue
                else:
                    results[run_name] = {'output': run_output.strip()}
                if delete_after_success:
                    try:
                        os.remove(run_path)
                    except:
                        log.exception('Failed to remove {}', run_path)
                    else:
                        log.info('Removed {}', run_path)
    return results


def parse_args():
    parser = argparse.ArgumentParser(description='Collect data to be '
                                     'submitted to the server')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plugins', action='store_true', help='Only run '
                       'plugins (no commands)')
    group.add_argument('--commands', action='store_true', help='Only run '
                       'one-shot commands (no plugins)')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    if not (args.plugins or args.commands):
        args.plugins = args.commands = True

    results = {
        'hostname': socket.gethostname(),
        'collected_at': datetime.datetime.utcnow().isoformat(),
    }

    if args.plugins:
        results['plugins'] = run_dir('plugins')

    if args.commands:
        results['commands'] = run_dir('commands', parse_output=False,
                                      delete_after_success=True,
                                      submit_failures=True)

    if not (results.get('plugins', False) or results.get('commands', False)):
        return

    if not os.path.exists(collected_dir):
        os.makedirs(collected_dir)
    collected_path = os.path.join(collected_dir, str(int(time.time())))
    open(collected_path, 'w').write(json.dumps(results))


if __name__ == '__main__':
    main()
