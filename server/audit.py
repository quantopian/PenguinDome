#!/usr/bin/env python3

import argparse
import datetime
import logbook
import os
import subprocess
import sys

from qlmdm import top_dir
from qlmdm.server import (
    get_db,
    open_issue,
    close_issue,
    snooze_issue,
    unsnooze_issue,
    get_open_issues,
    get_setting,
    get_port_setting,
    get_logger,
)

os.chdir(top_dir)
log = get_logger('audit')

problem_checks = {
    'not-reporting': {
        'grace-period': datetime.timedelta(days=2),
        'spec': {'submitted_at':
                 {'$lt': datetime.datetime.utcnow() -
                  datetime.timedelta(days=1)}}},
    'no-location': {
        'grace-period': datetime.timedelta(days=3),
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
        'grace-period': datetime.timedelta(days=1),
        'spec': {'plugins.eraagent.running': {'$not': {'$eq': True}}}},
    'eset-absent': {
        'spec': {'plugins.eset.installed': {'$not': {'$eq': True}}}},
    'eset-out-of-date': {
        'grace-period': datetime.timedelta(days=1),
        'spec': {'plugins.eset.recent': {'$not': {'$eq': True}}}},
    'eset-stopped': {
        'grace-period': datetime.timedelta(days=1),
        'spec': {'plugins.eset.running': {'$not': {'$eq': True}}}},
    'os-update-available': {
        'grace-period': datetime.timedelta(days=90),
        'spec': {'plugins.os_updates.release': {'$not': {'$eq': False}}}},
    'os-security-patches-available': {
        'grace-period': datetime.timedelta(days=3),
        'spec': {'$or': [{'plugins.os_info.distname': {'$ne': 'arch'},
                          'plugins.os_updates.security_patches':
                          {'$not': {'$eq': False}}},
                         {'plugins.os_info.distname': 'arch',
                          'arch_security_updates_at': {'$exists': True}}]}},
    'guest-session-enabled': {
        'spec': {'plugins.guest_session.enabled': {'$not': {'$eq': False}}}},
    'unencrypted-hard-drive': {
        'spec': {'plugins.hd_encryption.encrypted': {'$not': {'$eq': True}}}},
    'firewall-disabled': {
        'spec': {'plugins.firewall.status': {'$not': {'$eq': 'on'}}}},
    'screenlock-disabled': {
        'grace-period': datetime.timedelta(days=1),
        'spec': {'plugins.screenlock.enabled': {'$not': {'$eq': True}}}},
    'deprecated-port': {
        'grace-period': datetime.timedelta(hours=1)},
    'pending-patches': {
        'grace-period': datetime.timedelta(hours=1)},
    'expiring-certificate': {}
}


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
    audit_parser.add_argument(
        '--ignore-recent-alerts', action='store_true', help="Ignore whether "
        "we have already alerted in the past hour when deciding what to "
        "report, and don't record the alert for checking this later")
    audit_parser.add_argument('--ignore-snoozed', action='store_true',
                              help='Show alerts that are snoozed')
    audit_parser.add_argument(
        '--full', action='store_true', help='Same as --ignore-grace-period '
        '--ignore-recent-alerts --ignore-snoozed')
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
    if args.full:
        args.ignore_grace_period = args.ignore_recent_alerts = \
            args.ignore_snoozed = True

    db = get_db()

    for check_name, check in problem_checks.items():
        if 'spec' not in check:
            continue
        problems = [d for d in db.clients.find(check['spec'])]
        for problem in problems:
            open_issue(problem['hostname'], check_name)
        problem_hosts = [d['hostname'] for d in problems]
        close_issue({'$not': {'$in': problem_hosts}}, check_name)

    check_pending_patches()
    check_ssl_certificates()

    issues = get_open_issues()

    now = datetime.datetime.utcnow()
    # Slightly less than an hour, to avoid race conditions when running hourly.
    alert_threshold = now - datetime.timedelta(minutes=59)

    for key1, value1 in issues.items():
        key1_printed = False
        for key2, issue in value1.items():
            try:
                grace_period = problem_checks[issue['name']]['grace-period']
                grace_threshold = now - grace_period
            except KeyError:
                grace_threshold = now
            alert_ok = (args.ignore_recent_alerts or
                        'alerted_at' not in issue or
                        issue['alerted_at'] < alert_threshold)
            grace_ok = (args.ignore_grace_period or
                        issue['opened_at'] < grace_threshold)
            snooze_ok = (args.ignore_snoozed or
                         'unsnooze_at' not in issue or
                         issue['unsnooze_at'] < now)
            if alert_ok and grace_ok and snooze_ok:
                if not key1_printed:
                    print(key1)
                    key1_printed = True
                print('  {} since {}'.format(key2, issue['opened_at']))
                if not args.ignore_recent_alerts:
                    db.issues.update(
                        {'_id': issue['_id']}, {'$set': {'alerted_at': now}})


def snooze_handler(args):
    if not (args.host or args.issue_name or args.all):
        sys.exit('If you really want to snooze all issues for all hosts,\n'
                 'you need to specify --all.')

    if not (args.days or args.hours):
        args.days = 1

    now = datetime.datetime.utcnow()
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
        return

    with logbook.StreamHandler(sys.stdout, bubble=True):
        for doc in get_db().issues.find({'_id': {'$in': ids}}):
            log.info('Unsnoozed {} {} at {}', doc['hostname'], doc['name'],
                     doc['unsnoozed_at'])


def main():
    args = parse_args()

    args.func(args)


if __name__ == '__main__':
    main()
