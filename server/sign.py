#!/usr/bin/env python

import os
import shutil
import subprocess
import sys

from qlmdm import (
    top_dir,
    set_gpg,
    release_files_iter,
    signatures_dir,
    sign_file,
)

os.chdir(top_dir)
set_gpg('server')

shutil.rmtree(signatures_dir, ignore_errors=True)

for file in release_files_iter():
    sign_file(file)

try:
    subprocess.check_output((os.path.join('client', 'verify.py')),
                            stderr=subprocess.STDOUT)
except:
    sys.exit('Verify failed, try running {} again'.format(sys.argv[0]))
