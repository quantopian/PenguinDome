#!/usr/bin/env python

import argparse
import os
import shutil
import subprocess
import sys

from qlmdm import (
    top_dir,
    set_gpg,
    release_files_iter,
    signatures_dir,
    verify_signature,
    sign_file,
)
from qlmdm.server import get_logger

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
            signature = sign_file(file, overwrite=True)
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
                 format(e.output))


if __name__ == '__main__':
    main()
