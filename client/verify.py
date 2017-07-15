#!/usr/bin/env python

import os
import subprocess
import sys

from qlmdm import top_dir, set_gpg, release_files_iter

os.chdir(top_dir)
set_gpg('client')

errors = False

for file, signature_file in release_files_iter(with_signatures=True):
    try:
        output = subprocess.check_output(
            ('gpg', '--verify', signature_file, file),
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print('Bad signature for {}'.format(file))
        print(e.output.strip())
        errors = True

sys.exit(1 if errors else 0)
