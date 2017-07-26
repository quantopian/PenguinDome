#!/usr/bin/env python3

import argparse
import datetime
import logbook
import os
import pytz
import subprocess
import sys

from qlmdm import top_dir
from qlmdm.server import (
    get_db,
    open_issue,
    close_issue,
    snooze_issue,
    unsnooze_issue,
    suspend_host,
    unsuspend_host,
    get_open_issues,
    get_setting,
    get_port_setting,
    get_logger,
)

os.chdir(top_dir)
log = get_logger('issues')
now = datetime.datetime.utcnow()

problem_checks = {
    'not-reporting': {
        'grace-period': datetime.timedelta(hours=4),
        'spec': {'submitted_at':
                 {'$lt': now - datetime.timedelta(days=1)}}},
    'no-location': {
        'grace-period': datetime.timedelta(days=1),
        'spec': {'plugins.geolocation': 'unknown'}},
    'ssh-password-authentication': {
        'spec': {'$and': [
            {'plugins.sshd.status': 'running'},
            {'plugins.sshd.config.passwordauthentication': 'yes'}]}},
    'ssh-root-password-authentication': {
        'spec': {'$and': [
            {'plugins.sshd.status': 'running'},
            {'plugins.sshd.config.permitrootlogin': 'yes'}]}},
    'eraagent-absent': {
        'spec': {'plugins.eraagent.installed': {'$not': {'$eq': True}}}},
    'eraagent-stopped': {
        'grace-period': datetime.timedelta(hours=4),
        'spec': {'plugins.eraagent.running': {'$not': {'$eq': True}}}},
    'eset-absent': {
        'spec': {'plugins.eset.installed': {'$not': {'$eq': True}}}},
    'eset-out-of-date': {
        'grace-period': datetime.timedelta(hours=4),
        'spec': {'plugins.eset.recent': {'$not': {'$eq': True}}}},
    'eset-stopped': {
        'grace-period': datetime.timedelta(hours=4),
        'spec': {'plugins.eset.running': {'$not': {'$eq': True}}}},
    'os-update-available': {
        'grace-period': datetime.timedelta(days=90),
        'spec': {'plugins.os_updates.release': {'$not': {'$eq': False}}}},
    'os-security-patches-available': {
        'grace-period': datetime.timedelta(days=1),
        'spec': {'$or': [{'plugins.os_info.distname': {'$ne': 'arch'},
                          'plugins.os_updates.security_patches':
                          {'$not': {'$eq': False}}},
                         {'plugins.os_info.distname': 'arch',
                          'arch_security_updates_at': {'$exists': True}}]}},
    'guest-session-enabled': {
        'spec': {'plugins.guest_session.enabled': {'$not': {'$eq': False}}}},
    'unencrypted-hard-drive': {
        'spec': {'$or': [
            {'plugins.hd_encryption.encrypted': {'$eq': False}},
            {'plugins.hd_encryption.encrypted': {'$exists': False}}]}},
    'firewall-disabled': {
        'spec': {'plugins.firewall.status': {'$not': {'$eq': 'on'}}}},
    'screenlock-disabled': {
        'grace-period': datetime.timedelta(hours=4),
        'spec': {'plugins.screenlock.users.enabled': {'$not': {'$eq': True}}}},
    'deprecated-port': {
        'grace-period': datetime.timedelta(hours=1)},
    'pending-patches': {
        'grace-period': datetime.timedelta(hours=4)},
    'expiring-certificate': {}
}


# Yeah, this should really use pytest or something, whatevs.
#
# td = datetime.timedelta
# bh = business_hours
#
# testcases = (
#     (p('2017-07-23T11:00:00Z'), p('2017-07-23T12:00:00Z'), td(0)),
#     (p('2017-07-23T11:00:00Z'), p('2017-07-24T14:00:00Z'), td(hours=1)),
#     (p('2017-07-21T20:00:00Z'), p('2017-07-24T14:00:00Z'), td(hours=2)),
#     (p('2017-07-21T16:00:00Z'), p('2017-07-21T18:30:00Z'),
#      td(hours=2, minutes=30)),
#     (p('2017-07-19T18:15:00Z'), p('2017-07-21T14:20:00Z'),
#      td(hours=12, minutes=5)),
#     (p('2017-07-20T16:00:00Z'), p('2017-07-25T18:00:00Z'), td(hours=26)),
# )
# for t1, t2, expected in testcases:
#     assert bh(t1, t2) == expected

def to_local_time(dt):
    return dt.replace(tzinfo=pytz.utc).astimezone(
        pytz.timezone('US/Eastern'))


def business_hours(t1, t2):
    """Calculate timedelta of business hours from UTC times t1 to t2

    Very rough -- doesn't take into account holidays. This doesn't need to be
    perfect since it's OK for us to get occasional premature alerts. It's just
    meant to eliminate most of them.
    """

    td = datetime.timedelta  # makes things cleaner below
    # First, convert both times to local time
    t1 = to_local_time(t1)
    t2 = to_local_time(t2)

    if t2.hour > 16:
        t2 = t2.replace(hour=17, minute=0)

    accumulator = td(0)
    while t1 < t2:
        if t1.weekday() > 4:  # weekend
            t1 = t1.replace(hour=9, minute=0)
            t1 += td(days=7 - t1.weekday())
            continue
        if t1.hour < 9:
            t1 = t1.replace(hour=9, minute=0)
            continue
        if t1.hour > 16:
            t1 = t1.replace(hour=9, minute=0)
            t1 += td(days=1)
            continue
        if t1.date() < t2.date():
            accumulator += t1.replace(hour=17, minute=0) - t1
            t1 = t1.replace(hour=9, minute=0)
            t1 += td(days=1)
            continue
        accumulator += t2 - t1
        break

    return accumulator


def parse_args():
    parser = argparse.ArgumentParser(description='Check for and report on '
                                     'problems')
    parser.set_defaults(func=None)

    subparsers = parser.add_subparsers()

    audit_parser = subparsers.add_parser('audit',
                                         help='Audit and report on issues')
    audit_parser.add_argument(
        '--ignore-grace-period', action='store_true',
        help='Ignore alert grace period when deciding what to report')
    group = audit_parser.add_mutually_exclusive_group()
    group.add_argument(
        '--display-recent', action='store_true', default=None, help='Display '
        'recently displayed alerts (defaults to yes when running in a '
        'terminal, no otherwise)')
    group.add_argument(
        '--nodisplay-recent', dest='display_recent', action='store_false',
        default=None, help="Don't display recently displayed alerts")
    group = audit_parser.add_mutually_exclusive_group()
    group.add_argument(
        '--update-recent', action='store_true', default=None, help="Tag "
        "displayed alerts so they won't be displayed again for the next hour "
        "(defaults to tagging when run interactively, not otherwise)")
    group.add_argument(
        '--noupdate-recent', dest='update_recent', action='store_false',
        default=None, help="Don't tag displayed alerts")
    audit_parser.add_argument('--ignore-snoozed', action='store_true',
                              help='Show alerts that are snoozed')
    audit_parser.add_argument('--ignore-suspended', action='store_true',
                              help='Show alerts for suspended hosts')
    audit_parser.add_argument(
        '--full', action='store_true', help='Same as --ignore-grace-period '
        '--display-recent --ignore-snoozed (but NOT --ignore-suspended)')
    audit_parser.set_defaults(func=audit_handler)

    snooze_parser = subparsers.add_parser('snooze', help='Snooze alerts')
    group = snooze_parser.add_mutually_exclusive_group()
    group.add_argument(
        '--days', type=int, help='Snooze for this many days (default: 1 day)')
    group.add_argument('--hours', type=int, help='Snooze for this many hours')
    snooze_parser.add_argument(
        '--all', action='store_true', help='Snooze all alerts (required if '
        'neither --host nor --problem is specified')
    snooze_parser.add_argument('--host', action='append', help='Snooze the '
                               'specified host(s)')
    snooze_parser.add_argument('--issue-name', action='append', help='Snooze '
                               'the specified issue type(s)')
    snooze_parser.set_defaults(func=snooze_handler)

    unsnooze_parser = subparsers.add_parser('unsnooze', help='Unsnooze alerts')
    unsnooze_parser.add_argument(
        '--all', action='store_true', help='Unsnooze all alerts (required if '
        'neither --host nor --problem is specified')
    unsnooze_parser.add_argument('--host', action='append',
                                 help='Unsnooze the specified host(s)')
    unsnooze_parser.add_argument('--issue-name', action='append',
                                 help='Unsnooze the specified issue type(s)')
    unsnooze_parser.set_defaults(func=unsnooze_handler)

    suspend_parser = subparsers.add_parser('suspend', help='Suspend hosts')
    suspend_parser.add_argument('host', nargs='+', help='Host(s) to suspend')
    suspend_parser.set_defaults(func=suspend_handler)

    unsuspend_parser = subparsers.add_parser('unsuspend',
                                             help='Unsuspend hosts')
    unsuspend_parser.add_argument('host', nargs='+',
                                  help='Hosts(s) to unsuspend')
    unsuspend_parser.set_defaults(func=unsuspend_handler)

    close_parser = subparsers.add_parser('close', help='Close issues')
    close_parser.add_argument(
        '--all', action='store_true', help='Close all issues (required if '
        'neither --host nor --problem is specified')
    close_parser.add_argument('--host', action='append', help='Close issues '
                              'for the specified host(s)')
    close_parser.add_argument('--issue-name', action='append', help='Close '
                              'the specified issue type(s)')
    close_parser.set_defaults(func=close_handler)

    args = parser.parse_args()
    if not args.func:
        parser.error('No subcommand specified.')

    return args


def check_ssl_certificates():
    ports = get_setting('port')
    if isinstance(ports, int):
        ports = [ports]
    elif isinstance(ports, dict):
        ports = list(ports.keys())

    problem_hosts = []
    for port in ports:
        certificate_file = get_port_setting(port, 'ssl:certificate')
        if not get_port_setting(port, 'ssl:enabled', bool(certificate_file)):
            continue
        try:
            subprocess.check_output(
                ('openssl', 'x509', '-in', certificate_file, '-checkend',
                 str(60 * 60 * 24 * 7)), stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            hostname = 'server-port-{}'.format(port)
            problem_hosts.append(hostname)
            open_issue(hostname, 'expiring-certificate')
    close_issue({'$not': {'$in': list(problem_hosts)}}, 'expiring-certificate')


def check_pending_patches():
    db = get_db()
    problem_hosts = set()
    for patch in db.patches.find({'pending_hosts': {'$not': {'$size': 0}}}):
        for hostname in patch['pending_hosts']:
            open_issue(hostname, 'pending-patches')
            problem_hosts.add(hostname)
    close_issue({'$not': {'$in': list(problem_hosts)}}, 'pending-patches')


def audit_handler(args):
    def d(dt):
        return dt.strftime('%m/%d %H:%M')

    in_a_terminal = os.isatty(sys.stderr.fileno())
    if args.update_recent is None:
        args.update_recent = not in_a_terminal
    if args.display_recent is None:
        args.display_recent = in_a_terminal

    if args.full:
        args.ignore_grace_period = args.display_recent = \
            args.ignore_snoozed = True

    db = get_db()

    for check_name, check in problem_checks.items():
        if 'spec' not in check:
            continue
        problems = [d for d in db.clients.find(check['spec'])]
        for problem in problems:
            open_issue(problem['hostname'], check_name,
                       as_of=problem['plugins']['submitted_at'])
        problem_hosts = [d['hostname'] for d in problems]
        close_issue({'$not': {'$in': problem_hosts}}, check_name)

    check_pending_patches()
    check_ssl_certificates()

    issues = get_open_issues(include_suspended=args.ignore_suspended)

    # Slightly less than an hour, to avoid race conditions when running hourly.
    alert_threshold = now - datetime.timedelta(minutes=59)

    for key1, value1 in issues.items():
        key1_printed = False
        for key2, issue in value1.items():
            try:
                grace_period = problem_checks[issue['name']]['grace-period']
            except KeyError:
                grace_period = datetime.timedelta(0)
            alert_ok = (args.display_recent or
                        'alerted_at' not in issue or
                        issue['alerted_at'] < alert_threshold)
            grace_ok = (args.ignore_grace_period or
                        business_hours(issue['opened_at'], now) > grace_period)
            snooze_ok = (args.ignore_snoozed or
                         'unsnooze_at' not in issue or
                         issue['unsnooze_at'] < now)
            if issue.get('unsnooze_at', now) > now:
                snoozed = ' [snoozed until {}]'.format(d(issue['unsnooze_at']))
            else:
                snoozed = ''
            if alert_ok and grace_ok and snooze_ok:
                if not key1_printed:
                    print(key1)
                    key1_printed = True
                print('  {} since {}{}'.format(key2, d(issue['opened_at']),
                                               snoozed))
                if not in_a_terminal:
                    log.warn('{} {} since {}', key1, key2, issue['opened_at'])
                if args.update_recent:
                    db.issues.update(
                        {'_id': issue['_id']}, {'$set': {'alerted_at': now}})


def snooze_handler(args):
    if not (args.host or args.issue_name or args.all):
        sys.exit('If you really want to snooze all issues for all hosts,\n'
                 'you need to specify --all.')

    if not (args.days or args.hours):
        args.days = 1

    if args.days:
        then = now + datetime.timedelta(days=args.days)
    else:
        then = now + datetime.timedelta(hours=args.hours)

    hostname = (None if not args.host else
                args.host[0] if len(args.host) == 1 else
                {'$in': args.host})
    issue_name = (None if not args.issue_name else
                  args.issue_name[0] if len(args.issue_name) == 1
                  else {'$in': args.issue_name})
    ids = snooze_issue(hostname, issue_name, then)

    if not ids:
        print('No matching issues.')
        return

    with logbook.StreamHandler(sys.stdout, bubble=True):
        for doc in get_db().issues.find({'_id': {'$in': ids}}):
            log.info('Snoozed {} {} until {}', doc['hostname'], doc['name'],
                     then)


def unsnooze_handler(args):
    if not (args.host or args.issue_name or args.all):
        sys.exit('If you really want to unsnooze all issues for all hosts,\n'
                 'you need to specify --all.')

    hostname = (None if not args.host else
                args.host[0] if len(args.host) == 1 else
                {'$in': args.host})
    issue_name = (None if not args.issue_name else
                  args.issue_name[0] if len(args.issue_name) == 1
                  else {'$in': args.issue_name})
    ids = unsnooze_issue(hostname, issue_name)

    if not ids:
        print('No matching issues.')
        return

    with logbook.StreamHandler(sys.stdout, bubble=True):
        for doc in get_db().issues.find({'_id': {'$in': ids}}):
            log.info('Unsnoozed {} {} at {}', doc['hostname'], doc['name'],
                     doc['unsnoozed_at'])


def suspend_handler(args):
    matches = suspend_host(args.host)
    if not matches:
        print('No matching, unsuspended hosts.')
        return
    with logbook.StreamHandler(sys.stdout, bubble=True):
        for host in matches:
            log.info('Suspended {}', host)


def unsuspend_handler(args):
    matches = unsuspend_host(args.host)
    if not matches:
        print('No matching, suspended hosts.')
        return
    with logbook.StreamHandler(sys.stdout, bubble=True):
        for host in matches:
            log.info('Unsuspended {}', host)


def close_handler(args):
    if not (args.host or args.issue_name or args.all):
        sys.exit('If you really want to close all issues for all hosts,\n'
                 'you need to specify --all.')

    hostname = (None if not args.host else
                args.host[0] if len(args.host) == 1 else
                {'$in': args.host})
    issue_name = (None if not args.issue_name else
                  args.issue_name[0] if len(args.issue_name) == 1
                  else {'$in': args.issue_name})
    ids = close_issue(hostname, issue_name)

    if not ids:
        print('No matching issues.')
        return

    with logbook.StreamHandler(sys.stdout, bubble=True):
        for doc in get_db().issues.find({'_id': {'$in': ids}}):
            log.info('Manually closed {} {}', doc['hostname'], doc['name'])


def main():
    args = parse_args()

    args.func(args)


if __name__ == '__main__':
    main()
