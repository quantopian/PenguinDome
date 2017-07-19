#!/usr/bin/env python3

from itertools import chain
import os
import shutil
import subprocess
from tempfile import NamedTemporaryFile, mkdtemp
import time

from qlmdm import (
    top_dir,
    releases_dir,
    var_dir,
    release_file,
    set_gpg,
    release_files_iter,
    gpg_command,
)
from qlmdm.server import sign_file

set_gpg('server')
os.chdir(top_dir)

staging_dir = mkdtemp(dir=var_dir)
try:
    try:
        os.remove(release_file)
    except:
        pass
    release = int(time.time())
    release_file_path = os.path.join(staging_dir, release_file)
    os.makedirs(os.path.dirname(release_file_path))
    open(release_file_path, 'w').write(str(release) + '\n')
    subprocess.check_output(os.path.join('bin', 'sign'))
    sign_file(release_file, top_dir=staging_dir)
    os.makedirs(releases_dir, exist_ok=True)
    with NamedTemporaryFile('w+') as file_list, \
            NamedTemporaryFile('w+') as staging_file_list:
        release_files = release_files_iter(with_signatures=True)
        release_files = chain.from_iterable(release_files)
        file_list.write('\n'.join(release_files) + '\n')
        file_list.flush()

        staging_files = release_files_iter(with_signatures=True,
                                           top_dir=staging_dir)
        staging_files = chain.from_iterable(staging_files)
        staging_file_list.write('\n'.join(staging_files) + '\n')
        staging_file_list.flush()

        tar_file = os.path.join(releases_dir, '{}.tar'.format(release))
        subprocess.check_output(('tar', '--create', '--file', tar_file,
                                 '--files-from', file_list.name,
                                 '--directory', staging_dir,
                                 '--files-from', staging_file_list.name))
    gpg_command('--armor', '--sign', tar_file)
    assert os.path.exists(tar_file + '.asc')
finally:
    shutil.rmtree(staging_dir)

print('Built release {}'.format(release))
