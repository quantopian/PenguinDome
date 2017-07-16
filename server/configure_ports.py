#!/usr/bin/env python3

import argparse
from functools import partial
import os
import pprint
import re
import sys
from urllib.parse import urlparse, urlunparse

from qlmdm import set_setting
from qlmdm.server import (
    get_setting as get_server_setting,
    get_port_setting,
    set_setting as set_server_setting,
    save_settings as save_server_settings,
)
from qlmdm.client import (
    get_setting as get_client_setting,
    set_setting as set_client_setting,
    save_settings as save_client_settings,
)


def parse_args():
    parser = argparse.ArgumentParser(description='Add, remove, or configure '
                                     'ports for qlmdm server')

    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument('port', metavar='PORTNUMBER', type=int, action='store')

    options = argparse.ArgumentParser(add_help=False)
    group = options.add_mutually_exclusive_group()
    group.add_argument('--threaded', action='store_true', default=None,
                       help='Run server in mjlti-threaded mode')
    group.add_argument('--nothreaded', dest='threaded', default=None,
                       action='store_false',
                       help='Run server in single-threaded mode')
    group = options.add_mutually_exclusive_group()
    group.add_argument('--ssl', dest='ssl', action='store_true',
                       default=None, help='Enable SSL')
    group.add_argument('--nossl', dest='ssl', action='store_false',
                       default=None, help='Disable SSL')
    options.add_argument('--certificate', action='store',
                         help='SSL certificate file (also requires --key)')
    options.add_argument('--key', action='store',
                         help='SSL key file (also requires --certificate)')

    subparsers = parser.add_subparsers()

    show_parser = subparsers.add_parser('show-configuration',
                                        aliases=('show',),
                                        help='Show current configuration')
    show_parser.set_defaults(func=show_configuration)

    add_parser = subparsers.add_parser('add-port', parents=(parent, options),
                                       aliases=('add',),
                                       help='Enable a new port')
    add_parser.set_defaults(func=add_port)

    remove_parser = subparsers.add_parser('remove-port', parents=(parent,),
                                          aliases=('remove',),
                                          help='Remove a port')
    remove_parser.set_defaults(func=remove_port)

    configure_parser = subparsers.add_parser(
        'configure-port', aliases=('configure',),
        parents=(parent, options),
        help="Configure a port after adding it if it isn't already added")
    configure_parser.set_defaults(func=configure_port)

    client_parser = subparsers.add_parser(
        'configure-client', help='Configure the server URL for clients')
    client_parser.set_defaults(func=configure_client)
    client_parser.add_argument('--hostname', action='store', help='Host name '
                               'to put in server URL')
    client_parser.add_argument('--port', type=int, help='Port number')
    group = client_parser.add_mutually_exclusive_group()
    group.add_argument('--ssl', dest='ssl', action='store_true',
                       default=None, help='Use https:')
    group.add_argument('--nossl', dest='ssl', action='store_false',
                       default=None, help='Use http:')

    args = parser.parse_args()
    return args


def ports_iter():
    port = get_server_setting('port')
    if isinstance(port, int):
        yield port
        return
    for p in port:
        yield p


def port_config(port):
    config = {}
    config['threaded'] = get_port_setting(port, 'threaded')
    if get_port_setting(port, 'ssl'):
        config['ssl'] = {}
        config['ssl']['self_signed'] = get_port_setting(
            port, 'ssl:self_signed', False)
        cert = get_port_setting(port, 'ssl:certificate')
        config['ssl']['certificate'] = cert or 'MISSING'
        config['ssl']['enabled'] = get_port_setting(
            port, 'ssl:enabled', bool(cert))
        config['ssl']['key'] = \
            get_port_setting(port, 'ssl:key') or 'MISSING'
    return config


def show_configuration(args):
    config = {}
    for port in ports_iter():
        print('Port {}'.format(port))
        config = port_config(port)
        pformat = pprint.pformat(config)
        pformat = re.sub(r'^', '  ', pformat, re.MULTILINE)
        print(pformat)

    server_url = get_client_setting('server_url') or 'MISSING'
    print('Server URL: {}'.format(server_url))


def add_port(args):
    return configure_port(args, add=True)


def remove_port(args):
    port = args.port
    ports = get_server_setting('port')
    if not ports:
        sys.exit('There are no ports to remove!')
    if isinstance(ports, int) or len(ports) == 1:
        sys.exit("You can't remove the only configured port!")
    if port not in ports:
        sys.exit('Port {} is not currently configured'.format(port))
    if isinstance(ports, list):
        ports.remove(port)
    else:
        ports.pop(port)
    set_server_setting('port', ports)
    save_server_settings()
    print('Removed port {}.'.format(port))
    show_configuration(args)


def configure_port(args, add=False):
    changed = False
    port = args.port
    ports = get_server_setting('port', None)
    if not ports:
        ports = []
    elif isinstance(ports, int):
        ports = [ports]
    if isinstance(ports, list):
        ports = {port: {} for port in ports}
        set_server_setting('port', ports)

    if port in ports:
        if add:
            sys.exit('Port {} is already present.'.format(args.port))
        which = 'Configured'
    else:
        ports[port] = {}
        changed = True
        which = 'Added'

    port_settings = ports[port]
    gps = partial(get_port_setting, port)

    def ss(setting, value):
        nonlocal changed
        set_setting(port_settings, setting, value)
        changed = True

    if args.threaded is not None:
        if bool(gps('threaded')) != args.threaded:
            ss('threaded', args.threaded)

    if args.certificate and gps('ssl:certificate') != args.certificate:
        if not (args.key or gps('ssl:key')):
            sys.exit('You must specify both a certificate and a key.')
        if not os.path.exists(args.certificate):
            sys.exit('The certificate file {} does not exist'.format(
                args.certificate))
        ss('ssl:certificate', args.certificate)

    if args.key and gps('ssl:key') != args.key:
        if not gps('ssl:certificate'):
            sys.exit('You must specify both a certificate and a key.')
        if not os.path.exists(args.key):
            sys.exit('The key file {} does not exist'.format(
                args.key))
        ss('ssl:key', args.key)

    if args.ssl:
        if not (gps('ssl:certificate') and gps('ssl:key')):
            sys.exit('You must specify a certificate and key to enable SSL.')
        if not gps('ssl:enabled', bool(gps('ssl:certificate'))):
            ss('ssl:enabled', True)
    elif args.ssl is False:
        if gps('ssl:enabled', bool(gps('ssl:certificate'))):
            ss('ssl:enabled', False)

    if changed:
        save_server_settings()

        url = get_client_setting('server_url')
        if url:
            url = urlparse(url)
            if ':' in url[1]:
                _, client_port = url[1].split(':')
                client_port = int(client_port)
            else:
                client_port = {'http': 80, 'https': 443}[url[0]]
            client_ssl = {'http': False, 'https': True}[url[0]]
            if port == client_port and \
               client_ssl != gps('ssl:enabled', bool(gps('ssl:certificate'))):
                print('WARNING: Client is configured to use port {} and {}'
                      'using SSL.\n'
                      '         Should it be?'.format(
                          port, '' if client_ssl else 'not '))

        print('{} port {}.'.format(which, port))
        show_configuration(args)
    else:
        print('No changes.')


def configure_client(args):
    changed = False
    url = get_client_setting('server_url')
    if url:
        url = list(urlparse(url))
    else:
        url = ['', '', '', '', '', '']
    if ':' in url[1]:
        hostname, port = url[1].split(':')
        port = int(port)
    else:
        hostname = url[1]
        port = 443 if url[0] == 'https' else 80

    if args.hostname:
        if hostname != args.hostname:
            hostname = args.hostname
            changed = True

    if args.port:
        if port != args.port:
            port = args.port
            changed = True
        if port == 443 and args.ssl is None:
            args.ssl = True

    if args.ssl:
        if url[0] != 'https':
            url[0] = 'https'
            changed = True
    elif args.ssl is False:
        if url[0] != 'http':
            url[0] = 'http'
            changed = True

    if port == 443 and url[0] != 'https':
        print("WARNING: Are you sure you don't want to use SSL on port 443?")

    verbose_port = port or 80
    try:
        server_port_ssl = get_port_setting(
            verbose_port, 'ssl:enabled',
            bool(get_port_setting(verbose_port, 'ssl:certificate')))
    except:
        server_port_ssl = False
    if server_port_ssl and url[0] != 'https':
        print('WARNING: Port {} on the server is using SSL.\n'
              '         Does the client need to?'.format(verbose_port))
    elif not server_port_ssl and url[0] != 'http':
        print('WARNING: Port {} on the server is not using SSL.\n'
              '         Are you sure the client should?'.format(verbose_port))

    if not hostname:
        sys.exit('You must specify hostname.')
    if url[0] not in ('http', 'https'):
        changed = True
        url[0] = 'https' if port == 443 else 80
    if port and ((url[0] == 'http' and port != 80) or
                 (url[0] == 'https' and port != 443)):
        loc = '{}:{}'.format(hostname, port)
        if url[1] != loc:
            changed = True
            url[1] = loc
    else:
        url[1] = hostname
    url = urlunparse(url)
    url = re.sub(r'/+$', '', url)
    if changed:
        set_client_setting('server_url', url)
        save_client_settings()
        print('Changed server URL to {}'.format(url))
    else:
        print('Server URL is unchanged: {}'.format(url))


def main():
    args = parse_args()

    args.func(args)


if __name__ == '__main__':
    main()
