#!/usr/bin/env python

import argparse
import curses

from penguindome import set_gpg
from penguindome.server import patch_hosts, get_setting, get_logger
from penguindome.shell import (
    InteractionBroker,
    TerminalPeer,
    PenguinDomeServerPeer,
)

set_gpg('server')
log = get_logger('client_shell')


def interact(stdscr, broker):
    curses.raw()
    broker.interact()


def parse_args():
    parser = argparse.ArgumentParser(
        description='Request a remote shell on a client',
        epilog='Remote shell traffic travels through and is mediated by the '
        'server. This script tells the server to send a remote shell request '
        'to the specified client, Then connects to the server and waits for '
        'the client to initiate the remote shell. Once the remote shell is '
        'initiated, you can interact with it normally. To exit from the '
        'shell, hit Enter followed by "~." (tilde, then period).')
    parser.add_argument('hostname', metavar='HOSTNAME')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    log.info('Requesting remote shell from {}', args.hostname)
    with PenguinDomeServerPeer(
            'server', local_port=get_setting('local_port'),
            logger=log, client_hostname=args.hostname, useServerKeychain=True) as remote, \
            TerminalPeer() as terminal:
        host = args.hostname
        script = '#!/bin/bash\npython client/endpoints/shell.py {}\n'.format(
            remote.pipe_id)
        patch_hosts('client/commands/shell-{}'.format(remote.pipe_id),
                    patch_content=script.encode('utf8'),
                    hosts=host)
        broker = InteractionBroker(terminal, remote, poll_interval=0.2)
        print('Waiting for client to connect (once connected, use "~." to '
              'disconnect)...')
        remote.poll()
        curses.wrapper(interact, broker)


if __name__ == '__main__':
    main()
