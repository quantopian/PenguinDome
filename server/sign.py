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

import argparse
import os
import shutil
import subprocess
import sys

from penguindome import (
    top_dir,
    set_gpg,
    release_files_iter,
    signatures_dir,
    verify_signature,
)
from penguindome.server import get_logger, sign_file

os.chdir(top_dir)

log = get_logger('sign')


def parse_args():
    parser = argparse.ArgumentParser(description='Generate digital signatures '
                                     'for client files')
    parser.add_argument('--full', action='store_true', help='Regenerate all '
                        'signatures rather than only invalid ones')

    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    old_signatures = set()
    if args.full:
        log.info('Renerating all signatures')
        shutil.rmtree(signatures_dir, ignore_errors=True)
    elif os.path.exists(signatures_dir):
        for dirpath, dirnames, filenames in os.walk(signatures_dir):
            for f in filenames:
                old_signatures.add(os.path.join(dirpath, f))

    for file in release_files_iter():
        set_gpg('client')
        signature = verify_signature(file)
        if signature:
            log.debug('Preserving valid signature for {}', file)
        else:
            set_gpg('server')
            log.info('Signing {}', file)
            signature = sign_file(file)
        old_signatures.discard(signature)

    for file in old_signatures:
        log.info('Removing obsolete signature {}', file)
        os.unlink(file)

    try:
        subprocess.check_output(
            ('python', os.path.join('client', 'verify.py')),
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        sys.exit('Verify failed, try running bin/sign again. Output:\n{}'.
                 format(e.output.decode('ascii')))


if __name__ == '__main__':
    main()
