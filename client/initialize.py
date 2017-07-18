#!/usr/bin/env python3

import argparse
import os
from tempfile import NamedTemporaryFile
from textwrap import dedent
import shutil

from qlmdm import top_dir
from qlmdm.prompts import get_bool


os.chdir(top_dir)


parser = argparse.ArgumentParser(
    description='Finalize installation of the qlmdm client.',
)
parser.add_argument(
    '--prefix',
    metavar='PATH',
    default='/',
    help='The install prefix.',
)
parser.add_argument(
    '-y',
    '--no-prompt',
    action='store_false',
    dest='prompt',
    help='Do not prompt the user before installing or replacing the crontab',
)

args = parser.parse_args()

cron_file = os.path.join(args.prefix, 'etc/cron.d/qlmdm')
cron_exists = os.path.exists(cron_file)

if prompt:
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
            * * * * * root {}/bin/client-cron
        '''.format(top_dir)))
        temp_cron_file.flush()
        os.chmod(cron_file, 0o644)
        shutil.copy(temp_cron_file.name, cron_file)

    print('Installed {}'.format(cron_file))

print('Done!')
