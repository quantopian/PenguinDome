#!/usr/bin/env python3

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
