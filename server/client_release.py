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

from itertools import chain
import os
import shutil
import subprocess
from tempfile import NamedTemporaryFile, mkdtemp
import time

from penguindome import (
    top_dir,
    releases_dir,
    var_dir,
    commands_dir,
    release_file,
    set_gpg,
    release_files_iter,
    gpg_command,
)
from penguindome.server import sign_file

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
        release_files = tuple(chain.from_iterable(release_files))
        file_list.write('\n'.join(release_files) + '\n')
        file_list.flush()

        staging_files = release_files_iter(with_signatures=True,
                                           top_dir=staging_dir)
        staging_files = list(chain.from_iterable(staging_files))

        if not any(f.startswith(commands_dir) for f in release_files):
            os.makedirs(os.path.join(staging_dir, commands_dir))
            staging_files.append(commands_dir)

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
