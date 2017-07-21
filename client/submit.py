#!/usr/bin/env python3

import glob
import os

from qlmdm import top_dir, collected_dir, set_gpg
from qlmdm.client import server_request

os.chdir(top_dir)
set_gpg('client')

for collected in sorted(glob.glob(os.path.join(collected_dir, '*[0-9]'))):
    server_request('/qlmdm/v1/submit', data_path=collected,
                   exit_on_connection_error=True)
    os.unlink(collected)
