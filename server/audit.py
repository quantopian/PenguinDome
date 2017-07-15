#!/usr/bin/env python

import argparse
import datetime
import os

from qlmdm import top_dir, get_db, open_issue, close_issue, get_open_issues

os.chdir(top_dir)

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
        'spec': {'plugins.os_updates.security_patches':
                 {'$not': {'$eq': False}}}},
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
}


def parse_args():
    parser = argparse.ArgumentParser(description='Check for and report on '
                                     'problems')
    parser.add_argument('--ignore-grace-period', action='store_true',
                        help='Ignore alert grace period when deciding what to '
                        'report')
    parser.add_argument('--ignore-recent-alerts', action='store_true',
                        help="Ignore whether we have already alerted in the "
                        "past hour when deciding what to report, and don't "
                        "record the alert for checking this later")
    parser.add_argument('--full', action='store_true', help='Same as '
                        '--ignore-grace-period --ignore-recent-alerts')

    args = parser.parse_args()
    if args.full:
        args.ignore_grace_period = args.ignore_recent_alerts = True

    return args


def main():
    args = parse_args()
    db = get_db()

    for check_name, check in problem_checks.items():
        if 'spec' not in check:
            continue
        problems = [d for d in db.submissions.find(check['spec'])]
        for problem in problems:
            open_issue(problem['hostname'], check_name)
        problem_hosts = [d['hostname'] for d in problems]
        close_issue({'$not': {'$in': problem_hosts}}, check_name)

    problem_hosts = set()
    for patch in db.patches.find({'pending_hosts': {'$not': {'$size': 0}}}):
        for hostname in patch['pending_hosts']:
            open_issue(hostname, 'pending-patches')
            problem_hosts.add(hostname)
        close_issue({'$not': {'$in': list(problem_hosts)}}, 'pending-patches')

    issues = get_open_issues()

    now = datetime.datetime.utcnow()
    alert_threshold = now - datetime.timedelta(hours=1)

    for key1, value1 in issues.items():
        key1_printed = False
        for key2, issue in value1.items():
            try:
                grace_period = problem_checks[issue['name']]
                grace_threshold = now - grace_period
            except:
                grace_threshold = now
            alert_ok = (args.ignore_recent_alerts or
                        issue['alerted_at'] < alert_threshold)
            grace_ok = (args.ignore_grace_period or
                        issue['opened_at'] < grace_threshold)
            if alert_ok and grace_ok:
                if not key1_printed:
                    print(key1)
                    key1_printed = True
                print('  {} since {}'.format(key2, issue['opened_at']))
                if not args.ignore_recent_alerts:
                    db.issues.update(
                        {'_id': issue['_id']}, {'$set': {'alerted_at': now}})


if __name__ == '__main__':
    main()
