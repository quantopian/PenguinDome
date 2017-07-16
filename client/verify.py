#!/usr/bin/env python3

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
