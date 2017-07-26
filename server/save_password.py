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
from passlib.hash import pbkdf2_sha256

from penguindome.server import set_setting, save_settings


def parse_args():
    parser = argparse.ArgumentParser(
        description='Insert a username and encrypted password into the '
        'server settings')
    parser.add_argument('SETTING', help='Setting to add a '
                        'password to, e.g., download_release')
    parser.add_argument('USERNAME', help='Username to associate with the '
                        'specified password')
    parser.add_argument('PASSWORD', help='The password to assocate with the '
                        'specified username')
    return parser.parse_args()


def main():
    args = parse_args()
    setting_path = 'server_auth:{}:passwords:{}'.format(
        args.SETTING, args.USERNAME)
    hashed = pbkdf2_sha256.encrypt(args.PASSWORD, rounds=200000, salt_size=16)
    set_setting(setting_path, hashed)
    save_settings()


if __name__ == '__main__':
    main()
