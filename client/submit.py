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

import glob
import os
from requests.exceptions import HTTPError
import sys

from penguindome import top_dir, collected_dir, set_gpg
from penguindome.client import get_logger, server_request

log = get_logger('submit')
os.chdir(top_dir)
set_gpg('client')

for collected in sorted(glob.glob(os.path.join(collected_dir, '*[0-9]'))):
    try:
        server_request('/penguindome/v1/submit', data_path=collected,
                       exit_on_connection_error=True)
    except HTTPError as e:
        if e.response.status_code == 400:
            log.error('Server returned status code 400. '
                      'Renaming {} to {}.bad.', collected, collected)
            os.rename(collected, collected + '.bad')
            sys.exit(1)
    os.unlink(collected)
    log.debug('Successful submission of {}', collected)
