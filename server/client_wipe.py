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

from qlmdm import top_dir, set_gpg
from qlmdm.server import patch_hosts

os.chdir(top_dir)
set_gpg('server')


def parse_args():
    parser = argparse.ArgumentParser(description='Wipe user data from a host!')
    parser.add_argument('hostname', help='The host to wipe')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    patch_hosts('client/commands/wipe',
                patch_content=open('server/files/wipe.sh').read(),
                hosts=args.hostname)
    print('Scheduled wipe of {}'.format(args.hostname))


if __name__ == '__main__':
    main()
