from base64 import b64encode
from collections import defaultdict
import datetime
from mongo_proxy import MongoProxy
import os
from pymongo import MongoClient
from tempfile import NamedTemporaryFile

from qlmdm import (
    load_settings,
    get_setting as main_get_setting,
    set_setting as main_set_setting,
    get_logger as main_get_logger,
    save_settings as main_save_settings,
    signatures_dir,
    get_selectors as main_get_selectors,
    encrypt_document as main_encrypt_document,
    gpg_command,
    top_dir,
)

db = None


def get_setting(setting, default=None, check_defaults=True):
    return main_get_setting(load_settings('server'), setting, default,
                            check_defaults)


def get_port_setting(port, setting, default=None):
    global_setting = get_setting(setting, default)
    settings_port = get_setting('port')
    if isinstance(settings_port, int) or isinstance(settings_port, list):
        return global_setting
    return main_get_setting(settings_port[port], setting, global_setting,
                            check_defaults=False)


def set_setting(setting, value):
    return main_set_setting(load_settings('server'), setting, value)


def save_settings():
    main_save_settings('server')


def get_logger(name):
    return main_get_logger(get_setting, name)


def get_db():
    global db

    if db:
        return db

    database_name = get_setting('database:name')
    host = get_setting('database:host')

    if not host:
        connection = MongoClient()
    else:
        if not isinstance(host, str):
            host = ','.join(host)
        kwargs = {}
        replicaset = get_setting('database:replicaset')
        if replicaset:
            kwargs['replicaset'] = replicaset
        connection = MongoClient(host, **kwargs)

    newdb = connection[database_name]

    username = get_setting('database:username')
    if username:
        password = get_setting('database:password')
        newdb.authenticate(username, password)

    db = MongoProxy(newdb)
    return db


def patch_hosts(patch_path, patch_mode=0o755, patch_content=b'', signed=True,
                hosts=None):
    db = get_db()
    if hosts is None:
        hosts = db.clients.distinct('hostname')
    if isinstance(hosts, str):
        hosts = [hosts]
    conflict = db['patches'].find_one({'path': patch_path,
                                       'pending_hosts': {'$in': hosts}})
    if conflict:
        conflicting_hosts = list(set(hosts) & set(conflict['pending_hosts']))
        conflicting_hosts.sort()
        raise Exception('Patch for {} conflicts with patch ID {} on hosts {}'.
                        format(patch_path, conflict['_id'], conflicting_hosts))

    # Somebody please explain to me why b64encode returns bytes rather than
    # str in python3, when the whole, entire prupose of b64encode is to turn
    # arbitrary bytes into ASCII. This is stupid.

    files = [
        {
            'path': patch_path,
            'mode': patch_mode,
            'content': b64encode(patch_content).decode('ascii'),
        },
    ]

    if signed:
        files.append({
            'path': os.path.join(signatures_dir, patch_path + '.sig'),
            'mode': 0o644,
            'content': b64encode(sign_data(patch_content)).decode('ascii'),
        })

    result = db['patches'].insert_one({
        'submitted_at': datetime.datetime.utcnow(),
        'pending_hosts': hosts,
        'completed_hosts': [],
        'files': files,
    })
    return result.inserted_id


def open_issue(hostname, issue_name):
    """Opens an issue for the specified hostname if there isn't one"""
    db = get_db()
    existing = db.issues.find_one({'hostname': hostname,
                                   'name': issue_name,
                                   'closed_at': {'$exists': False}})
    if not existing:
        db.issues.insert_one({'hostname': hostname,
                              'name': issue_name,
                              'opened_at': datetime.datetime.utcnow()})


def close_issue(hostname, issue_name):
    """Closes any open issues for the specified host and issue name"""
    db = get_db()
    db.issues.update_many({'hostname': hostname,
                           'name': issue_name,
                           'closed_at': {'$exists': False}},
                          {'$set': {'closed_at': datetime.datetime.utcnow()}})


def snooze_issue(hostname, issue_name, snooze_until):
    """Snooze any open issues for the specified host and issue name

    Returns the ids of the snoozed issues."""

    db = get_db()

    spec = {'closed_at': {'$exists': False},
            '$or': [{'unsnooze_at': {'$exists': False}},
                    {'unsnooze_at': {'$lt': snooze_until}}]}

    if hostname:
        spec['hostname'] = hostname

    if issue_name:
        spec['name'] = issue_name

    ids = [d['_id'] for d in db.issues.find(spec, projection=['_id'])]
    if not ids:
        return []

    db.issues.update_many(
        {'_id': {'$in': ids}},
        {'$set': {'snoozed_at': datetime.datetime.now(),
                  'unsnooze_at': snooze_until}})
    return ids


def unsnooze_issue(hostname, issue_name):
    """Unsnooze any snoozed issues for the specified host and issue name

    Returns the ids of the unsnoozed issues."""

    db = get_db()

    now = datetime.datetime.utcnow()
    spec = {'closed_at': {'$exists': False}, 'unsnooze_at': {'$gt': now}}

    if hostname:
        spec['hostname'] = hostname

    if issue_name:
        spec['name'] = issue_name

    ids = [d['_id'] for d in db.issues.find(spec, projection=['_id'])]
    if not ids:
        return []

    db.issues.update_many(
        {'_id': {'$in': ids}},
        {'$set': {'unsnoozed_at': now, 'unsnooze_at': now}})
    return ids


def get_open_issues(primary_key='host', hostname=None, issue_name=None):
    """Returns a dictionary of matching open issues

    You can specify 'host' or 'issue' as the primary key. The secondary key is
    whichever one you don't specify."""

    if primary_key == 'host':
        primary_key = 'hostname'
        secondary_key = 'name'
    elif primary_key == 'issue':
        primary_key = 'name'
        secondary_key = 'hostname'
    else:
        raise Exception('Unrecognized primary key {}'.format(primary_key))

    issues = defaultdict(dict)
    db = get_db()
    spec = {'closed_at': {'$exists': False}}
    if hostname:
        spec['hostname'] = hostname
    if issue_name:
        spec['name'] = issue_name
    for issue in db.issues.find(spec):
        issues[issue[primary_key]][issue[secondary_key]] = issue

    return dict(issues)


def get_selectors():
    return main_get_selectors(get_setting)


def encrypt_document(doc, log=None):
    return main_encrypt_document(get_setting, doc, log=log)


def sign_file(file, top_dir=top_dir):
    signature_file = os.path.join(top_dir, signatures_dir, file + '.sig')
    file = os.path.join(top_dir, file)
    os.makedirs(os.path.dirname(signature_file), exist_ok=True)
    gpg_command('--detach-sig', '-o', signature_file, file)
    return signature_file[len(top_dir)+1:]


def sign_data(data):
    with NamedTemporaryFile() as data_file, \
         NamedTemporaryFile() as signature_file:
        data_file.write(data)
        data_file.flush()
        gpg_command('--detach-sig', '-o', signature_file.name, data_file.name)
        return signature_file.read()
