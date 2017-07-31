#!/usr/bin/env python

import argparse
import logbook
import sys

from penguindome.server import (
    valid_client_parameters,
    set_client_parameter,
    get_client_parameter,
    get_client_parameters,
    get_logger,
)

log = get_logger('client_parameters')


def parse_args():
    parser = argparse.ArgumentParser(
        description='Administer client parameters')
    subparsers = parser.add_subparsers()

    ls_parser = subparsers.add_parser('ls', help='List client parameters',
                                      aliases=('list',))
    ls_parser.set_defaults(func=ls_handler)
    ls_parser.add_argument('--hostname', action='append',
                           help='Client(s) to list')
    ls_parser.add_argument('--parameter', action='append',
                           choices=valid_client_parameters,
                           help='Parameter(s) to list')

    set_parser = subparsers.add_parser('set', help='Set client parameter')
    set_parser.set_defaults(func=set_handler)
    set_parser.add_argument('--hostname', help='Client to set', required=True)
    set_parser.add_argument('--parameter', help='Parameter to set',
                            choices=valid_client_parameters,
                            required=True)
    set_parser.add_argument('value', metavar='VALUE', nargs='+')

    unset_parser = subparsers.add_parser('unset',
                                         help='Unset client parameter')
    unset_parser.set_defaults(func=unset_handler)
    unset_parser.add_argument('--hostname', help='Client to unset',
                              required=True)
    unset_parser.add_argument('--parameter', help='Parameter to unset',
                              choices=valid_client_parameters,
                              required=True)

    args = parser.parse_args()
    return args


def ls_handler(args):
    results = [t for t in get_client_parameters(args.hostname, args.parameter)]
    columns = ('Hostname', 'Parameter', 'Value')
    divides = ('--------', '---------', '-----')
    results = [columns, divides] + results
    if len(results) > 2:
        column_widths = [max(len(t[col] or '') for t in results)
                         for col in range(len(columns))]
        for r in results:
            widened = ('{v!s:{w}}'.format(v=r[i], w=column_widths[i])
                       for i in range(len(columns)))
            print('  '.join(widened))


def set_handler(args):
    old_value = get_client_parameter(args.hostname, args.parameter)

    try:
        old = set_client_parameter(args.hostname, args.parameter, args.value)
    except Exception as e:
        sys.exit('Failed to set parameter: {}'.format(e))

    if not old_value:
        with logbook.StreamHandler(sys.stdout, bubble=True):
            log.info('Set parameter {} for host {} to {}',
                     args.parameter, args.hostname, args.value)
    elif old:
        with logbook.StreamHandler(sys.stdout, bubble=True):
            log.info('Changed parameter {} for host {} from {} to {}',
                     args.parameter, args.hostname, old, args.value)
    else:
        print('No changes.')


def unset_handler(args):
    try:
        old = set_client_parameter(args.hostname, args.parameter, None)
    except Exception as e:
        sys.exit('Failed to unset parameter: {}'.format(e))

    if old:
        with logbook.StreamHandler(sys.stdout, bubble=True):
            log.info('Unset parameter {} for host {} (was {})', args.parameter,
                     args.hostname, old)
    else:
        print('No changes.')


def main():
    args = parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
