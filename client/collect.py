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

import argparse
import datetime
import os
import re
import subprocess
import socket
import stat
import sys
from tempfile import NamedTemporaryFile
import threading
import time

from penguindome import (
    top_dir,
    collected_dir,
    plugins_dir,
    commands_dir,
    signatures_dir,
    set_gpg,
)
from penguindome.client import get_logger, encrypt_document
import penguindome.json as json

os.chdir(top_dir)
set_gpg('client')

# Some commands the plugins use are in /sbin or /usr/sbin on some
# distributions, and it isn't always in the search path used by cron scripts.
for d in ('/sbin', '/usr/sbin'):
    if d not in os.environ['PATH'].split(':'):
        os.environ['PATH'] += ':' + d

log = get_logger('collect')


def run_file(run_path, run_name, results, parse_output=True,
             delete_after_success=False, submit_failures=False):
    log.debug('Running {}', run_path)
    with NamedTemporaryFile('w+') as stderr_file:
        try:
            run_output = subprocess.check_output(
                run_path,
                stderr=stderr_file.fileno()).decode('ascii')
        except subprocess.CalledProcessError as e:
            log.exception('Failed to execute {}', run_path)
            output = e.output.decode('ascii').strip()
            if output:
                log.info('Output of failed script:\n{}', output)
            stderr_file.seek(0)
            stderr = stderr_file.read().strip()
            if stderr:
                log.info('Stderr of failed script:\n{}', stderr)
            if submit_failures:
                results[run_name] = {
                    'stdout': e.output.decode('ascii'),
                    'stderr': stderr,
                    'returncode': e.returncode,
                }
            else:
                return
        else:
            if parse_output:
                try:
                    results[run_name] = json.loads(run_output)
                except:
                    log.exception('Output of {} failed to parse', run_path)
                    return
            else:
                results[run_name] = {'output': run_output.strip()}
            if delete_after_success:
                try:
                    os.remove(run_path)
                    sig_file = os.path.join(signatures_dir,
                                            run_path + '.sig')
                    try:
                        os.remove(sig_file)
                    except:
                        log.warn('Failed to remove {}', sig_file)
                except:
                    log.exception('Failed to remove {}', run_path)
                else:
                    log.info('Removed {}', run_path)
        finally:
            log.debug('Finished with {}', run_path)


def run_dir(dir_path, parse_output=True, delete_after_success=False,
            submit_failures=False):
    results = {}
    if not os.path.exists(dir_path):
        log.debug('Skipping nonexistent directory {}', dir_path)
        return
    saw_names = set()
    threads = []
    for run_tail in os.listdir(dir_path):
        run_path = os.path.join(dir_path, run_tail)
        if run_tail.endswith('~'):
            log.debug('Skipping {}', run_path)
            continue
        if run_tail.startswith('.'):
            log.debug('Skipping {}', run_path)
            continue
        run_name = re.sub(r'\.[^.]+$', '', run_tail)
        if run_name in saw_names:
            log.error('Skipping file with duplicate name {}',
                      run_path)
            continue
        saw_names.add(run_name)
        run_stat = os.stat(run_path)
        run_mode = run_stat.st_mode
        if not stat.S_ISREG(run_mode):
            log.debug('Skipping non-file {}', run_path)
            continue
        if not os.access(run_path, os.X_OK):
            log.debug('Skipping non-executable {}', run_path)
            continue
        args = (run_path, run_name, results)
        kwargs = {'parse_output': parse_output,
                  'delete_after_success': delete_after_success,
                  'submit_failures': submit_failures}
        if True:  # Change to False to disable threading
            thread = threading.Thread(
                target=run_file,
                args=args,
                kwargs=kwargs)
            thread.start()
            threads.append(thread)
        else:
            run_file(*args, **kwargs)
    for thread in threads:
        thread.join()
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


def runlevel_info():
    try:
        output = subprocess.check_output(
            'systemctl list-units --type target; runlevel; who -r', shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
    output = output.decode('ascii')
    return output


def main():
    args = parse_args()

    if not (args.plugins or args.commands):
        args.plugins = args.commands = True

    results = {
        'hostname': socket.gethostname(),
        'collected_at': datetime.datetime.utcnow(),
    }

    before_runlevel = runlevel_info()

    if args.plugins:
        results['plugins'] = run_dir(plugins_dir, submit_failures=True)

    if args.commands:
        results['commands'] = run_dir(commands_dir, parse_output=False,
                                      delete_after_success=True,
                                      submit_failures=True)

    after_runlevel = runlevel_info()

    if not (results.get('plugins', False) or results.get('commands', False)):
        return

    if before_runlevel != after_runlevel:
        # If the runlevel changes while we are running, it's probaby because
        # the machine is in the process of rebooting, in which case the odds
        # are that some of the plugins returned bad data and we shouldn't send
        # anything to the server.
        sys.exit('Aborting because runlevel changed')

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
