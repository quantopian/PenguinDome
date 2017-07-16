#!/usr/bin/env python3

import argparse

from qlmdm import set_gpg, patch_hosts

set_gpg('server')


def parse_args():
    parser = argparse.ArgumentParser(description='Queue a patch for one or '
                                     'more  hosts')
    parser.add_argument('--host', action='append', help='Host(s) on which to '
                        'execute command (default is all)')
    parser.add_argument('--mode', type=lambda m: int(m, 8), help='Mode for '
                        'patched file (specify in octal, default 0755)')
    parser.add_argument('target_path', help='Relative path of file on '
                        'destination systems')
    parser.add_argument('source_file', help='Local file containing patch '
                        'content')

    args = parser.parse_args()

    return args


def main():
    args = parse_args()
    kwargs = {}
    if args.mode:
        kwargs['patch_mode'] = args.mode
    kwargs['patch_content'] = open(args.source_file, 'rb').read()
    kwargs['hosts'] = args.host if args.host else None
    patch_hosts(args.target_path, **kwargs)


if __name__ == '__main__':
    main()
