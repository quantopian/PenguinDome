#!/usr/bin/env python3

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

from qlmdm import top_dir, collected_dir, set_gpg
from qlmdm.client import get_logger, encrypt_document

os.chdir(top_dir)
set_gpg('client')

# Some commands the plugins use are in /sbin or /usr/sbin on some
# distributions, and it isn't always in the search path used by cron scripts.
for d in ('/sbin', '/usr/sbin'):
    if d not in os.environ['PATH'].split(':'):
        os.environ['PATH'] += ':' + d

log = get_logger('collect')


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
        with NamedTemporaryFile('w+') as stderr_file:
            try:
                run_output = subprocess.check_output(
                    run_path,
                    stderr=stderr_file.fileno()).decode('ascii')
            except subprocess.CalledProcessError as e:
                log.exception('Failed to execute {}', run_path)
                log.info('Output of failed script:\n{}',
                         e.output.decode('ascii'))
                stderr_file.seek(0)
                stderr = stderr_file.read()
                log.info('Stderr of failed script:\n{}', stderr)
                if submit_failures:
                    results[run_name] = {
                        'stdout': e.output.decode('ascii'),
                        'stderr': stderr,
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
        results['plugins'] = run_dir('plugins', submit_failures=True)

    if args.commands:
        results['commands'] = run_dir('commands', parse_output=False,
                                      delete_after_success=True,
                                      submit_failures=True)

    if not (results.get('plugins', False) or results.get('commands', False)):
        return

    results, updates = encrypt_document(results, log=log)
    if updates:
        log.info('Encrypted private data before transmission to server')

    os.makedirs(collected_dir, exist_ok=True)
    collected_path = os.path.join(collected_dir, str(int(time.time())))
    with open(collected_path, 'w') as f:
        try:
            f.write(json.dumps(results))
        except:
            os.unlink(collected_path)
            raise
        log.debug('Saved collected data to {}', collected_path)


if __name__ == '__main__':
    main()
