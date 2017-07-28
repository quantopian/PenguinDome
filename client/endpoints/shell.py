#!/usr/bin/env python

# This script is used by the server to initiate a remote shell on the client.
# It should never be called directly.

import argparse
from contextlib import ExitStack
from daemon import DaemonContext
import sys

from penguindome import set_gpg
from penguindome.client import get_logger
from penguindome.shell import (
    InteractionBroker,
    PenguinDomeServerPeer,
)
from penguindome.shell.client import PexpectPeer


def background_code(args):
    log = get_logger('shell')
    pipe_id = args.pipe_id
    log.info('Initiating shell with pipe ID {}', pipe_id)
    try:
        set_gpg('client')
        with PenguinDomeServerPeer('client', pipe_id) as remote, \
                PexpectPeer('/bin/bash') as shell:
            broker = InteractionBroker(shell, remote)
            broker.interact()
    except:
        log.exception()
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--foreground', action='store_true')
    parser.add_argument('pipe_id', metavar='PIPE-ID')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    if args.foreground:
        manager = ExitStack
    else:
        manager = DaemonContext
    with manager():
        background_code(args)


if __name__ == '__main__':
    main()
