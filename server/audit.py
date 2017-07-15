#!/usr/bin/env python

import datetime
import os

from qlmdm import top_dir, get_db

os.chdir(top_dir)


def ready_to_alert(doc):
    return('alerted_at' not in doc or
           datetime.datetime.utcnow() - doc['alerted_at'] >
           datetime.timedelta(hours=1))


problem_checks = [
    {'name': 'not-reporting',
     'grace-period': datetime.timedelta(days=2),
     'spec': {'submitted_at':
              {'$lt': datetime.datetime.utcnow() -
               datetime.timedelta(days=1)}}},
    {'name': 'no-location',
     'grace-period': datetime.timedelta(days=3),
     'spec': {'plugins.geolocation': 'unknown'}},
    {'name': 'ssh-password-authentication',
     'grace-period': datetime.timedelta(0),
     'spec': {'$and': [
         {'plugins.sshd.status': 'running'},
         {'plugins.sshd.config.passwordauthentication': 'yes'}]}},
    {'name': 'ssh-root-password-authentication',
     'grace-period': datetime.timedelta(0),
     'spec': {'$and': [
         {'plugins.sshd.status': 'running'},
         {'plugins.sshd.config.permitrootlogin': 'yes'}]}},
    {'name': 'eraagent-absent',
     'grace-period': datetime.timedelta(0),
     'spec': {'plugins.eraagent.installed': {'$not': {'$eq': True}}}},
    {'name': 'eraagent-stopped',
     'grace-period': datetime.timedelta(days=1),
     'spec': {'plugins.eraagent.running': {'$not': {'$eq': True}}}},
    {'name': 'eset-absent',
     'grace-period': datetime.timedelta(0),
     'spec': {'plugins.eset.installed': {'$not': {'$eq': True}}}},
    {'name': 'eset-out-of-date',
     'grace-period': datetime.timedelta(days=1),
     'spec': {'plugins.eset.recent': {'$not': {'$eq': True}}}},
    {'name': 'eset-stopped',
     'grace-period': datetime.timedelta(days=1),
     'spec': {'plugins.eset.running': {'$not': {'$eq': True}}}},
    {'name': 'os-update-available',
     'grace-period': datetime.timedelta(days=90),
     'spec': {'plugins.os_updates.release': {'$not': {'$eq': False}}}},
    {'name': 'os-security-patches-available',
     'grace-period': datetime.timedelta(days=3),
     'spec': {'plugins.os_updates.security_patches':
              {'$not': {'$eq': False}}}},
    {'name': 'guest-session-enabled',
     'grace-period': datetime.timedelta(0),
     'spec': {'plugins.guest_session.enabled': {'$not': {'$eq': False}}}},
    {'name': 'unencrypted-hard-drive',
     'grace-period': datetime.timedelta(0),
     'spec': {'plugins.hd_encryption.encrypted': {'$not': {'$eq': True}}}},
    {'name': 'firewall-disabled',
     'grace-period': datetime.timedelta(0),
     'spec': {'plugins.firewall.status': {'$not': {'$eq': 'on'}}}},
    {'name': 'screenlock-disabled',
     'grace-period': datetime.timedelta(days=1),
     'spec': {'plugins.screenlock.enabled': {'$not': {'$eq': True}}}},
]

db = get_db()

for check in problem_checks:
    problems = [d for d in db.submissions.find(check['spec'])]
    for problem in problems:
        unresolved = db.issues.find_one({
            'hostname': problem['hostname'],
            'name': check['name'],
            'closed': {'$exists': False}})
        if not unresolved:
            unresolved = {
                'hostname': problem['hostname'],
                'name': check['name'],
                'opened': datetime.datetime.utcnow()}
            db.issues.insert_one(unresolved)
        to_alert = ready_to_alert(unresolved)
        threshold = datetime.datetime.utcnow() - check['grace-period']
        if to_alert and unresolved['opened'] < threshold:
            print('{} {} since {}'.format(
                check['name'], problem['hostname'], unresolved['opened']))
            db.issues.update({'_id': unresolved['_id']},
                             {'$set': {'alerted_at':
                                       datetime.datetime.utcnow()}})
    problem_hosts = [d['hostname'] for d in problems]
    db.issues.update({'name': check['name'],
                      'hostname': {'$not': {'$in': problem_hosts}}},
                     {'$set': {'closed': datetime.datetime.utcnow()}})

for stale_patch in db.patches.find(
        {'submitted_at': {'$lt': datetime.datetime.utcnow() -
                          datetime.timedelta(days=1)},
         'pending_hosts': {'$not': {'$size': 0}}}):
    file_records = stale_patch['files']
    file_paths = (r['path'] for r in file_records)
    to_alert = ready_to_alert(stale_patch)
    if not to_alert:
        continue
    print('Patch to {} still pending for {} since {}'.format(
        ', '.join(file_paths), ', '.join(stale_patch['pending_hosts']),
        stale_patch['submitted_at']))
    db.patches.update({'_id': stale_patch['_id']},
                      {'$set': {'alerted_at':
                                datetime.datetime.utcnow()}})
