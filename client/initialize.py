#!/usr/bin/env python

import os
from tempfile import NamedTemporaryFile
from textwrap import dedent
import shutil

from qlmdm import top_dir
from qlmdm.prompts import get_bool

os.chdir(top_dir)

cron_file = '/etc/cron.d/qlmdm'
cron_exists = os.path.exists(cron_file)

if cron_exists:
    prompt = 'Do you want to replace the crontab?'
else:
    prompt = 'Do you want to install the crontab?'

do_crontab = get_bool(prompt, not cron_exists)

if do_crontab:
    with NamedTemporaryFile() as temp_cron_file:
        temp_cron_file.write(dedent('''\
            * * * * * root {}/bin/client-cron
        '''.format(top_dir)))
        temp_cron_file.flush()
        os.chmod(cron_file, 0644)
        shutil.copy(temp_cron_file.name, cron_file)

    print('Installed {}'.format(cron_file))
