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
import os
from tempfile import NamedTemporaryFile
from textwrap import dedent
import shutil
import subprocess
import sys

from penguindome import top_dir
from penguindome.prompts import get_bool


def main():
    os.chdir(top_dir)

    parser = argparse.ArgumentParser(
        description='Finalize installation of the PenguinDome client.',
    )
    parser.add_argument(
        '--prefix', metavar='PATH', default='/',
        help='The install prefix.')
    parser.add_argument(
        '-y', '--no-prompt', action='store_false', dest='prompt',
        help='Do not prompt the user before installing or replacing the '
        'crontab')

    args = parser.parse_args()

    cron_file = os.path.join(args.prefix, 'etc/cron.d/penguindome')
    cron_exists = os.path.exists(cron_file)

    if args.prompt:
        if cron_exists:
            prompt = 'Do you want to replace the crontab?'
        else:
            prompt = 'Do you want to install the crontab?'

        do_crontab = get_bool(prompt, not cron_exists)
    else:
        do_crontab = True

    if do_crontab:
        with NamedTemporaryFile('w+') as temp_cron_file:
            temp_cron_file.write(dedent('''\
                SHELL=/bin/bash
                * * * * * root {}/bin/client-cron &>/dev/null
            '''.format(top_dir)))
            temp_cron_file.flush()
            os.chmod(temp_cron_file.name, 0o644)

            # ensure the etc/cron.d directory exists
            os.makedirs(os.path.dirname(cron_file), exist_ok=True)
            shutil.copy(temp_cron_file.name, cron_file)

        print('Installed {}'.format(cron_file))

        cron_exists = True

    if cron_exists:
        enable_cron_service(args.prompt)

    print('Done!')


def enable_cron_service(ask):
    for service in ('cron', 'cronie'):
        if not subprocess.call('systemctl list-unit-files {0}.service | '
                               'fgrep -q -s {0}.service'.format(service),
                               shell=True):
            cron_service = service
            break
    else:
        sys.stderr.write(
            'Warning: Could not determine name of cron service. Cron may not\n'
            '         be running, so PenguinDome crontab may not run.\n')
        return

    for check, action in (('enabled', 'enable'), ('active', 'start')):
        good = not subprocess.call(
            ('systemctl', '--quiet', 'is-{}'.format(check), cron_service))

        if good:
            continue

        if ask:
            prompt = 'Do you want to {} the {} service?'.format(
                action, cron_service)
            doit = get_bool(prompt, True)
            if not doit:
                return

        subprocess.check_call(('systemctl', action, cron_service))


if __name__ == '__main__':
    main()
