#!/usr/bin/env python

"""Arch security updates manager

Responsibilities of this script;

* Fetch archives of arch-security mailing list, scan for updates, and put them
  into the database.

* When a security update first appears, flag all Arch clients that have that
  package installed, so that the audit script can detect that and trigger an
  issue.

* Whenever an Arch client reports that it has no pending updates with a
  timestamp newer than the flag mentioned above, clear the flag.

Responsibilities of the os_updates client plugin:

* Always report unknown for security updates, since it doesn't know which
  updates are for security.

* Always report false for release updates, since there are releases too often
  to treat them as anything other than patches.

* Report list of all installed packages, so that the server can check them for
  security updates.

Responsibilities of the audit script:

* Use Arch-specific query spec fragment for os-security-patches-available
  check.

"""

import argparse
import datetime
import dateutil.parser
import gzip
from io import BytesIO
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError
import re
import requests

from qlmdm.server import get_db, get_logger, arch_security_flag

log = get_logger('plugin_managers/arch_os_updates')


def download_arch_security():
    db = get_db()
    collection = db.arch_security_updates
    collection.create_index([('package', ASCENDING),
                             ('announced_at', ASCENDING)], unique=True)

    this_month = datetime.datetime.now().replace(day=1)

    def month_url(dt):
        return dt.strftime('https://lists.archlinux.org/pipermail/'
                           'arch-security/%Y-%B.txt.gz')

    try:
        archive_file = month_url(this_month)
        response = requests.get(archive_file)
        response.raise_for_status()
    except:
        last_month = this_month - datetime.timedelta(days=1)
        archive_file = month_url(last_month)
        response = requests.get(archive_file)
        response.raise_for_status()

    date_re = re.compile(r'^From .*\s(\S+\s+\d+)\s+(\d+:\d+:\d+)\s+(\d+)$')
    package_re = re.compile(r'^Subject: .*\] ([^:]+):')

    updates = []
    matched_one = False
    for line in (l.decode('utf-8') for l in
                 gzip.open(BytesIO(response.content), 'r')):
        match = date_re.match(line)
        if match:
            g = match.groups()
            date = '{} {} {} UTC'.format(g[0], g[2], g[1])
            dt = dateutil.parser.parse(date)
            continue
        match = package_re.match(line)
        if match:
            package = match.group(1)
            matched_one = True

            try:
                collection.insert_one({'package': package,
                                       'announced_at': dt})
            except DuplicateKeyError:
                pass
            else:
                log.info('Identified Arch security update for {}, '
                         'announced at {}', package, dt)
                updates.append((package, dt))

    if not matched_one:
        log.warn('Did not match any packages in {}', archive_file)

    return updates


def flag_impacted_clients(package, dt):
    spec = {'plugins.os_info.distname': 'arch',
            'plugins.os_updates.installed_packages': package,
            '$or': [{arch_security_flag: {'$exists': False}},
                    {arch_security_flag: {'$lt': dt}}]}
    db = get_db()
    for doc in db.clients.find(spec, projection=['hostname']):
        log.info('Flagging client {} for update of Arch package {}',
                 doc['hostname'], package)
    db.clients.update_many(spec, {'$set': {arch_security_flag: dt}})


def clear_obsolete_flags():
    db = get_db()

    spec = {arch_security_flag: {'$exists': True},
            'plugins.os_updates.patches': False}
    projection = ['_id', 'hostname', arch_security_flag,
                  'plugins.submitted_at']
    for doc in db.clients.find(spec, projection):
        if doc['plugins']['submitted_at'] > doc[arch_security_flag]:
            db.update_one({'_id': doc['_id']},
                          {'$unset': {arch_security_flag: True}})
            log.info('Cleared Arch security updates flag from {}',
                     doc['hostname'])


def parse_args():
    parser = argparse.ArgumentParser(description='Manager Arch Linux security '
                                     'update tracking')
    parser.add_argument('--download', action='store_true',
                        help='Download new update announcemets')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    if args.download:
        for package, dt in download_arch_security():
            flag_impacted_clients(package, dt)

    clear_obsolete_flags()


if __name__ == '__main__':
    main()
