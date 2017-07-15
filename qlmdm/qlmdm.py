from collections import defaultdict
import datetime
from base64 import b64encode
import json
import logbook
from mongo_proxy import MongoProxy
import os
from pymongo import MongoClient
import re
import requests
import stat
import subprocess
from tempfile import NamedTemporaryFile
import yaml

top_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
gpg_private_dir = os.path.join('server', 'keyring')
gpg_public_dir = os.path.join('client', 'keyring')
gpg_private_home = os.path.join(top_dir, gpg_private_dir)
gpg_public_home = os.path.join(top_dir, gpg_public_dir)
release_subdirs = ('client', 'qlmdm')
client_settings = None
server_settings = None
var_dir = os.path.join(top_dir, 'var')
releases_dir = os.path.join(var_dir, 'client_releases')
collected_dir = os.path.join(var_dir, 'collected')
release_file = os.path.join('client', 'release.txt')
signatures_dir = 'signatures'
db = None


def release_files_iter(with_signatures=False, top_dir=top_dir):
    for dirpath, dirnames, filenames in os.walk(top_dir):
        if dirpath == top_dir:
            for i in range(len(dirnames) - 1, -1, -1):
                if dirnames[i] not in release_subdirs:
                    del dirnames[i]
            filenames = []
        for i in range(len(dirnames) - 1, -1, -1):
            if dirnames[i].startswith('.#'):
                del dirnames[i]
        for filename in filenames:
            if filename.startswith('.#'):
                continue
            if filename.endswith('~'):
                continue
            if filename.endswith('.pyc'):
                continue
            path = os.path.join(dirpath, filename)
            if not stat.S_ISREG(os.stat(path).st_mode):
                continue
            relative_path = path[len(top_dir)+1:]
            if with_signatures:
                yield (relative_path,
                       os.path.join('signatures', relative_path + '.sig'))
            else:
                yield relative_path


def set_gpg(mode):
    if mode == 'server':
        os.environ['GNUPGHOME'] = gpg_private_home
    elif mode == 'client':
        os.environ['GNUPGHOME'] = gpg_public_home
    else:
        raise Exception('Internal error: Unrecognized GPG mode {}'.format(
            mode))


def get_client_settings():
    global client_settings

    if not client_settings:
        client_settings_file = os.path.join(top_dir, 'client', 'settings.yml')
        client_settings = yaml.load(open(client_settings_file))

    if 'server_url' in client_settings:
        client_settings['server_url'] = \
            re.sub(r'/+$', '', client_settings['server_url'])

    return client_settings


def get_server_settings():
    global server_settings

    if not server_settings:
        server_settings_file = os.path.join(top_dir, 'server', 'settings.yml')
        server_settings = yaml.load(open(server_settings_file))

    return server_settings


def server_request(cmd, data=None, data_path=None):
    server_url = get_client_settings()['server_url']
    if data and data_path:
        raise Exception('Both data and data_path specified')
    with NamedTemporaryFile() as temp_data_file, \
            NamedTemporaryFile() as signature_file:
        if data:
            data = json.dumps(data)
            temp_data_file.write(data)
            temp_data_file.flush()
            data_path = temp_data_file.name
        else:
            data = open(data_path).read()
        subprocess.check_output(('gpg', '--armor', '--batch', '--yes',
                                 '--detach-sign', '-o', signature_file.name,
                                 data_path), stderr=subprocess.STDOUT)
        signature_file.seek(0)
        post_data = {
            'data': data,
            'signature': signature_file.read(),
        }

    response = requests.post('{}{}'.format(server_url, cmd),
                             data=post_data, timeout=60)
    response.raise_for_status()
    return response


def verify_signature(file, top_dir=top_dir, raise_errors=False):
    signature_file = os.path.join(top_dir, signatures_dir, file + '.sig')
    file = os.path.join(top_dir, file)
    try:
        subprocess.check_output(('gpg', '--verify', signature_file, file),
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        if raise_errors:
            raise
        return None
    return signature_file[len(top_dir)+1:]


def sign_file(file, top_dir=top_dir, overwrite=False):
    signature_file = os.path.join(top_dir, signatures_dir, file + '.sig')
    file = os.path.join(top_dir, file)
    try:
        os.makedirs(os.path.dirname(signature_file))
    except:
        pass
    cmd = ['gpg', '--batch', '--detach-sig', '-o', signature_file, file]
    if overwrite:
        cmd.insert(1, '--yes')
    subprocess.check_output(cmd)


def sign_data(data):
    with NamedTemporaryFile() as data_file, \
         NamedTemporaryFile() as signature_file:
        data_file.write(data)
        data_file.flush()
        subprocess.check_output(('gpg', '--yes', '--batch', '--detach-sig',
                                 '-o', signature_file.name, data_file.name))
        return signature_file.read()


def get_db():
    global db

    if db:
        return db

    server_settings = get_server_settings()
    database_settings = server_settings['database']
    database_name = database_settings.get('name', 'qlmdm')

    host = database_settings.get('host', None)

    if not host:
        connection = MongoClient()
    else:
        if not isinstance(host, basestring):
            host = ','.join(host)
        kwargs = {}
        replicaset = database_settings.get('replicaset', None)
        if replicaset:
            kwargs['replicaset'] = replicaset
        connection = MongoClient(host, **kwargs)

    newdb = connection[database_name]

    username = database_settings.get('username', None)
    if username:
        password = database_settings.get('password')
        newdb.authenticate(username, password)

    db = MongoProxy(newdb)
    return db


def patch_hosts(patch_path, patch_mode=0755, patch_content='', signed=True,
                hosts=None):
    db = get_db()
    if hosts is None:
        hosts = db['submissions'].distinct('hostname')
    if isinstance(hosts, basestring):
        hosts = [hosts]
    conflict = db['patches'].find_one({'path': patch_path,
                                       'pending_hosts': {'$in': hosts}})
    if conflict:
        conflicting_hosts = list(set(hosts) & set(conflict['pending_hosts']))
        conflicting_hosts.sort()
        raise Exception('Patch for {} conflicts with patch ID {} on hosts {}'.
                        format(patch_path, conflict['_id'], conflicting_hosts))
    files = [
        {
            'path': patch_path,
            'mode': patch_mode,
            'content': b64encode(patch_content),
        },
    ]

    if signed:
        files.append({
            'path': os.path.join(signatures_dir, patch_path + '.sig'),
            'mode': 0644,
            'content': b64encode(sign_data(patch_content)),
        })

    result = db['patches'].insert_one({
        'submitted_at': datetime.datetime.utcnow(),
        'pending_hosts': hosts,
        'completed_hosts': [],
        'files': files,
    })
    return result.inserted_id


def get_logger(settings, name):
    try:
        handler_name = settings['logging']['handler']
    except:
        handler_name = 'stderr'
    handler_name += 'handler'
    handler_name = next(d for d in dir(logbook) if d.lower() == handler_name)
    handler = logbook.__dict__[handler_name]
    kwargs = {}
    for kwarg in (a for a in settings.get('logging', {})
                  if a not in ('handler', 'level')):
        kwargs[kwarg] = settings['logging'][kwarg]
    handler(**kwargs).push_application()
    try:
        level = settings['logging']['level']
    except:
        level = None
    level = logbook.__dict__[level.upper()]
    logbook.compat.redirect_logging()
    return logbook.Logger('qlmdm-' + name, level=level)


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
    db.issues.update({'hostname': hostname,
                      'name': issue_name,
                      'closed_at': {'$exists': False}},
                     {'$set': {'closed_at': datetime.datetime.utcnow()}})


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
