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
import re
import stat
import sys

from penguindome import set_gpg
from penguindome.server import patch_hosts

set_gpg('server')


def parse_args():
    parser = argparse.ArgumentParser(description='Queue a script or command '
                                     'on one or more hosts')
    parser.add_argument('--host', action='append', help='Host(s) on which to '
                        'execute command (default is all)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', action='store', help='Script or executable '
                       'to queue')
    group.add_argument('--command', action='store', help='Shell command to '
                       'queue')
    parser.add_argument('--name', help='Name to store results under in '
                        'database (default is basename of specified file)')

    args = parser.parse_args()

    if args.file:
        if not os.path.exists(args.file) or \
           not stat.S_ISREG(os.stat(args.file).st_mode):
            sys.exit('{} is not a regular file'.format(args.file))

    if not args.name:
        if not args.file:
            sys.exit('You must specify --name with --command')
        args.name = os.path.basename(os.path.splitext(args.file)[0])

    if re.search(r'[^-\w]', args.name):
        sys.exit('Command name must contain only alphanumerics and hyphens')

    return args


def main():
    args = parse_args()
    if args.file:
        data = open(args.file, 'rb').read()
    else:
        data = '#!/bin/bash\n{}\n'.format(args.command).encode()
    patch_hosts(os.path.join('client', 'commands', args.name),
                patch_content=data,
                hosts=args.host if args.host else None)


if __name__ == '__main__':
    main()
