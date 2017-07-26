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

import os
import subprocess
import sys

from qlmdm import top_dir, set_gpg, release_files_iter, verify_signature

os.chdir(top_dir)
set_gpg('client')

errors = False

for file in release_files_iter():
    try:
        verify_signature(file, raise_errors=True)
    except subprocess.CalledProcessError as e:
        print('Bad signature for {}'.format(file))
        print(e.output.decode('ascii').strip())
        errors = True

sys.exit(1 if errors else 0)
