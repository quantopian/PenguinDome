#!/usr/bin/env python3

# Quantopian, Inc. licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

from base64 import b64encode, b64decode
from bson import ObjectId
import datetime
from flask import Flask, request, Response, abort
from functools import wraps
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from multiprocessing import Process, RLock
import threading
import os
from passlib.hash import pbkdf2_sha256
from pymongo import ASCENDING
from pymongo.operations import IndexModel
import signal
import sys
import tempfile
import time
import redis
import redis_collections
from uuid import uuid4

from penguindome import (
    top_dir,
    set_gpg,
    releases_dir,
    gpg_command,
)
import penguindome.json as json
from penguindome.encryption import Encryptor
from penguindome.server import (
    get_logger,
    get_setting as get_server_setting,
    get_port_setting,
    get_db,
    open_issue,
    close_issue,
    encrypt_document,
    audit_trail_write,
)


log = None

os.chdir(top_dir)
set_gpg('server')
redis_pipes_db = redis.Redis(host='127.0.0.1', port=6379, db=0)
redis_encryptors_db = redis.Redis(host='127.0.0.1', port=6379, db=1)

pipes_lock = RLock()

app = Flask(__name__)


def log_deprecated_port(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        issue_name = 'deprecated-port'
        try:
            hostname = json.loads(request.form['data'])['hostname']
            ok = True
        except Exception:
            log.error('Failed to parse request data')
            ok = False
            hostname = request.remote_addr
        if app.config['deprecated_port']:
            log.warn('Host {} connected to deprecated port', hostname)
            if ok:
                if open_issue(hostname, issue_name):
                    log.info('Opened {} issue for {}', issue_name, hostname)
        else:
            if ok:
                doc = close_issue(hostname, issue_name)
                if doc:
                    log.info('Closed {} issue for {}', issue_name, hostname)
        return f(*args, **kwargs)
    return wrapper


def set_werkzeug_hostname(f):
    """Put client hostname in werkzeug logs"""

    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            hostname = json.loads(request.form['data'])['hostname']
        except Exception:
            hostname = None
        ret = f(*args, **kwargs)
        if hostname:
            request.environ['REMOTE_ADDR'] = hostname
        return ret
    return wrapper


def no_auth_needed(auth_name, mandatory=False):
    auth_info = get_server_setting(auth_name)
    if not auth_info:
        if mandatory:
            raise Exception('No authentication information configured in {}'.
                            format(auth_name))
        log.debug('Request permitted: authentication is not mandatory')
        return True
    return False


def check_ip_auth(auth_name):
    auth_info = get_server_setting(auth_name + ':ipranges')
    if not auth_info:
        log.debug('No auth: no IP ranges configured in {}', auth_name)
        return False
    try:
        remote_addr = IPv4Address(request.remote_addr)
    except Exception:
        try:
            remote_addr = IPv6Address(request.remote_addr)
        except Exception:
            log.debug("No auth: can't parse IP address {}",
                      request.remote_addr)
            return False
    for range_string in auth_info:
        try:
            ip_range = IPv4Network(range_string)
        except Exception:
            try:
                ip_range = IPv6Network(range_string)
            except Exception:
                raise Exception('Invalid address range {} in {}'.format(
                    range_string, auth_name))
        if remote_addr in ip_range:
            log.debug('Auth success: {} is in {}', remote_addr, ip_range)
            return True
    log.debug('No auth: no matching IP ranges for {} in {}', remote_addr,
              auth_name)


def check_password(auth_name):
    # Get list of users who are allowed access
    users = get_server_setting(auth_name + ':users') or []
    if isinstance(users, str):
        users = [users]
    users = {u: None for u in users}

    # Get list of groups who are allowed access
    groups = get_server_setting(auth_name + ':groups') or []
    if isinstance(groups, str):
        groups = [groups]

    # Get users for authorized groups
    for group in groups:
        group_users = get_server_setting('groups:' + group) or []
        if isinstance(group_users, str):
            group_users = [group_users]
        if group_users:
            users.update({u: None for u in group_users})
        else:
            log.warn('check_password: group {} is empty', group)

    # Warn about and remove invalid users
    for user in list(users.keys()):
        users[user] = get_server_setting('users:' + user)
        if not users[user]:
            log.warn('check_password: user {} has no password', user)
            del users[user]

    auth_info = get_server_setting(auth_name + ':passwords') or {}
    users.update(auth_info)
    if not users:
        log.debug('No auth: no passwords configured in {}', auth_name)
        return False

    if not request.authorization:
        log.debug('No auth: no username specified in request')
        return False
    try:
        password_hash = users[request.authorization.username]
    except KeyError:
        # N.B. One does not log usernames from authentication requests, in
        # case the user accidentally typed the password in the username field,
        # so that one doesn't accidentally log passwords.
        log.debug('No auth: invalid username for {}', auth_name)
        return False
    if not pbkdf2_sha256.verify(request.authorization.password, password_hash):
        # It's OK to log the username here, since we've already confirmed that
        # it's a valid username, not a password.
        log.warn('No auth: incorrect password for {} in {}',
                 request.authorization.username, auth_name)
        return False
    log.info('check_password: authenticated {} for {}',
             request.authorization.username, auth_name)
    return True


def flush_content(f):
    """Make sure we read the content so keep-alive doesn't get messed up

    Not needed if @verify_signature is guaranteed to be called, since it also
    reads the content."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        request.data
        return f(*args, **kwargs)
    return wrapper


def require_httpauth(auth_name, mandatory=True):
    """Authenticate a request

    `auth_name` is the server configuration setting containing the
    authentication information for the request. If it's empty and `mandatory`
    is True, an exception is raised; otherwise, the request is allowed to
    proceed (i.e., whether an endpoint with optional authentication has it is
    enforced by the configuration file).

    The authentication information can contain the subkeys `passwords`,
    `ipranges`, `users`, and/or `groups`.

    `ipranges` is a list of IP ranges. If the remote address of the request
    falls in any of the specified ranges, then the authentication succeeds with
    no need for a username and password.

    `passwords` is a dictionary of username / pbkdf2_sha256 hashes. If the
    username specified by the user matches any of the usernames in the
    dictionary, then the authentication succeeds if the password matches the
    stored hash.

    `users` is a list of one or more configured server users who are allowed to
    access the endpoint; their usernames and passwords will be checked.

    `groups` is a list of one or more configured server groups who are allowed
    to access the endpoing; the usernames and passwords of all users in all of
    the groups will be checked.
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            log.debug('require_httpauth: starting for {}', auth_name)
            if not (no_auth_needed(auth_name, mandatory=mandatory) or
                    check_ip_auth(auth_name) or check_password(auth_name)):
                log.debug('require_httpauth: returning 401 for {}', auth_name)
                return Response(
                    response='Login required',
                    status=401,
                    headers={
                        'WWW-Authenticate': 'Basic realm="Login Required"'})
            return f(*args, **kwargs)
        return wrapper
    return decorator


def verify_signature(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            data = request.form['data']
        except Exception:
            remote_addr = getattr(request, 'remote_addr', None)
            # Probably just somebody port-scanning us, not worth logging as
            # an error and making people waste time investigating.
            if remote_addr:
                log.info('Ignoring empty request from {}'.format(
                    remote_addr))
            else:
                log.info('Ignoring empty request with no remote address')
            return('error')
        try:
            signature = request.form['signature']
        except Exception:
            # We're not logging the data here because it may contain
            # sensitive info that should not be logged. Perhaps I am being
            # too paranoid about this. ¯\_(ツ)_/¯
            hostname = getattr(data, 'hostname', None)
            remote_addr = getattr(request, 'remote_addr', None)
            log.error('Ignoring malformed request (no signature) from '
                      'host {}, addr {}'.format(hostname, remote_addr))
            return('error')
        with tempfile.NamedTemporaryFile('w+') as data_file, \
                tempfile.NamedTemporaryFile('w+') as signature_file:
            data_file.write(data)
            data_file.flush()
            signature_file.write(signature)
            signature_file.flush()
            try:
                gpg_command('--verify', signature_file.name,
                            data_file.name)
            except Exception:
                hostname = getattr(data, 'hostname', None)
                remote_addr = getattr(request, 'remote_addr', None)
                log.error('Ignoring malformed request (bad signature) from '
                          'host {}, addr {}'.format(hostname, remote_addr))
                return('error')
        return f(*args, **kwargs)
    return wrapper


def strip_dates(d):
    for key in list(d.keys()):
        if key.endswith('_at'):
            del d[key]
        elif isinstance(d[key], dict):
            strip_dates(d[key])


def key_name(key, prefix):
    return prefix + '.' + key if prefix else key


def short_value(value):
    value = str(value)
    return '...' if len(value) > 40 else value


def dict_changes(old, new, prefix=None, changes=None, audit_trail=None):
    if changes is None:
        changes = []
        audit_trail = []
    keys = sorted(list(set(old.keys()) | set(new.keys())))
    for key, name in ((key, key_name(key, prefix)) for key in keys):
        if key not in new:
            changes.append('deleted {} ({})'.format(
                name, short_value(old[key])))
            audit_trail.append({
                'key': name,
                'action': 'delete',
                'old': old[key]})
        elif key not in old:
            changes.append('added {} ({})'.format(name, short_value(new[key])))
            audit_trail.append({
                'key': name,
                'type': 'add',
                'new': new[key]})
        elif type(old[key]) != type(new[key]):  # noqa
            changes.append('type change {} ({} -> {}, new value {})'.format(
                name, type(old[key]), type(new[key]), short_value(new[key])))
            audit_trail.append({
                'key': name,
                'type': 'change',
                'old': old[key],
                'new': new[key]})
        elif key.endswith('-encrypted'):
            # Backward compatibility until all clients are submitting encrypted
            # data with hashes.
            if not (isinstance(old[key], dict) and
                    isinstance(new[key], dict)):
                continue
            if old[key]['hash'] == new[key]['hash']:
                continue
            changes.append('changed {} (encrypted)'.format(name))
            audit_trail.append({
                'key': name,
                'type': 'change',
                'old': old[key],
                'new': new[key]})
        elif isinstance(old[key], dict):
            dict_changes(old[key], new[key], name, changes, audit_trail)
        elif isinstance(old[key], list):
            # This will work much better if plugins maintain consistent
            # ordering in lists.
            list_changed = False
            if len(old[key]) != len(new[key]):
                changes.append(
                    'length change {}[] ({} -> {}, new value {})'.format(
                        name, len(old[key]), len(new[key]),
                        short_value(str(new[key]))))
                list_changed = True
            else:
                for i in range(len(old[key])):
                    if isinstance(old[key][i], dict):
                        this_changes, _ = dict_changes(
                            old[key][i], new[key][i], '{}[{}]'.format(name, i),
                            [], [])
                        if this_changes:
                            changes.extend(this_changes)
                            list_changed = True
                    elif str(old[key][i]) != str(new[key][i]):
                        changes.append('changed {}[{}] ({} -> {})'.format(
                            name, i,
                            short_value(old[key][i]),
                            short_value(new[key][i])))
                        list_changed = True
            if list_changed:
                audit_trail.append({
                    'key': name,
                    'type': 'change',
                    'old': old[key],
                    'new': new[key]})
        elif str(old[key]) != str(new[key]):
            changes.append('changed {} ({} -> {})'.format(
                name, short_value(old[key]), short_value(new[key])))
            audit_trail.append({
                'key': name,
                'type': 'change',
                'old': old[key],
                'new': new[key]})
    return changes, audit_trail


@app.route('/PenguinDome/v1/submit', methods=('POST',))
@app.route('/penguindome/v1/submit', methods=('POST',))
@verify_signature
@log_deprecated_port
@set_werkzeug_hostname
def submit():
    db = get_db()
    which = []
    now = datetime.datetime.utcnow()
    try:
        data = json.loads(request.form['data'])
    except json.decoder.JSONDecodeError as e:
        log.exception('Failed to parse request data as JSON. Content=<<<{}>>>',
                      request.data)
        return Response(str(e), status=400)

    hostname = data['hostname']
    spec = {'hostname': hostname}
    update = {
        'submitted_at': now,
        'hostname': hostname,
    }
    if 'plugins' in data:
        data['plugins']['submitted_at'] = now
        update['plugins'] = data['plugins']
        which.append('plugins')
    if data.get('commands', {}):
        for name, output in data['commands'].items():
            output['submitted_at'] = now
            update['commands.{}'.format(name)] = output
        which.append('commands')
    if which:
        old = db.clients.find_one(spec)
        update_result = db.clients.update_one(
            spec, {'$set': update,
                   '$unset': {'suspended': True}})
        if update_result.modified_count == 0:
            db.clients.save(update)
            log.info('Added new client: {}', hostname)
        log.info('Successful submission of {} by {}',
                 ', '.join(which), hostname)
        if old:
            new = db.clients.find_one(spec)
            strip_dates(old)
            strip_dates(new)
            new, updates = encrypt_document(new)
            if updates:
                db.clients.update_one({'_id': new['_id']}, updates)
                log.info('Encrypted secret data for {} in document {}',
                         hostname, new['_id'])
            changes, audit_trail = dict_changes(old, new)
            for change in changes:
                log.info('Change for {}: {}', hostname, change)
            if audit_trail:
                audit_trail_write({'audited_at': now, 'hostname': hostname},
                                  audit_trail)
        return('ok')
    else:
        log.error('Empty submission from {}', hostname)
        return('error')


@app.route('/PenguinDome/v1/update', methods=('POST',))
@app.route('/penguindome/v1/update', methods=('POST',))
@verify_signature
@log_deprecated_port
@set_werkzeug_hostname
def update():
    db = get_db()
    data = json.loads(request.form['data'])
    hostname = data['hostname']
    old_release = data['old_release']
    releases = sorted(r for r in os.listdir(releases_dir)
                      if r.endswith('.asc'))
    response_data = {}
    if len(releases) == 0:
        response_data['status'] = 'current'
    else:
        current_release_file = releases[-1]
        current_release_number = \
            int(current_release_file[0:current_release_file.index('.')])
        if old_release >= current_release_number:
            response_data['status'] = 'current'
            log.debug('{} is current ({})', hostname, current_release_number)
        else:
            log.info('Sending release {} to {} (currently at {})',
                     current_release_number, hostname, old_release)
            response_data['status'] = 'out-of-date'
            response_data['current_release'] = current_release_number
            response_data['update'] = open(
                os.path.join(releases_dir, current_release_file)).read()

    patches = [{'id': str(d['_id']), 'files': d['files']}
               for d in db.patches.find({'pending_hosts': hostname},
                                        projection=['files'])]
    if patches:
        log.info('Sending patches {} ({}) to {}',
                 ', '.join(p['id'] for p in patches),
                 ', '.join(f['path'] for p in patches for f in p['files']),
                 hostname)
        response_data['patches'] = patches

    return json.dumps(response_data)


@app.route('/PenguinDome/v1/acknowledge_patch', methods=('POST',))
@app.route('/penguindome/v1/acknowledge_patch', methods=('POST',))
@verify_signature
@log_deprecated_port
@set_werkzeug_hostname
def acknowledge_patch():
    db = get_db()
    data = json.loads(request.form['data'])
    _id = data['id']
    hostname = data['hostname']
    db.patches.update_one(
        {'_id': ObjectId(_id)}, {'$push': {'completed_hosts': hostname},
                                 '$pull': {'pending_hosts': hostname}})
    log.info('{} acknowledged patch {}', hostname, _id)
    return 'ok'


@app.route('/PenguinDome/v1/download_release', methods=('GET',))
@app.route('/penguindome/v1/download_release', methods=('GET',))
@flush_content
@require_httpauth('server_auth:download_release', mandatory=False)
def download_release():
    try:
        all_files = os.listdir(releases_dir)
        tar_files = (f for f in all_files if f.endswith('.tar'))
        filename = sorted(tar_files, reverse=True)[0]
        latest_tar_file = os.path.join(releases_dir, filename)
    except Exception as e:
        return Response(str(e), status=404)

    def generate():
        with open(latest_tar_file, 'rb') as f:
            while True:
                msg = f.read(8192)
                if not msg:
                    break
                yield msg

    return Response(response=generate(),
                    status=200,
                    mimetype='application/tar',
                    headers={'Content-Disposition':
                             'attachment; filename={}'.format(filename)})


# Signing messages sent to the server is an expensive operation since it
# involves saving the message to disk, asking GnuPG to generate a separate
# signature file for it, and reading the signature file back into memory. We're
# doing that over and over since both the client and server ends of the pipe
# are pinging the server constantly to see if there is any new data from the
# other end, so it is silly for us to use GnuPG signing. Therefore, each end of
# the pipe gets an AES encryptor set up when it is opened, and we use that to
# encrypt the data rather than signing. Note that the key and IV are generated
# in a deterministic fashion from the UUID of the pipe, so they are not
# intended to be "secret" per se. The GnuPG messages weren't secret either,
# since we were just signing, not encryption, so this is no worse. The point of
# this is to prevent tampering and corruption in transit, not to ensure
# secrecy. For that, maybe use SSL, hmm?

@app.route('/PenguinDome/v1/server_pipe/server/create', methods=('POST',))
@app.route('/penguindome/v1/server_pipe/server/create', methods=('POST',))
@flush_content
@require_httpauth('server_auth:pipe_create')
@verify_signature
def pipe_create():
    data = json.loads(request.form['data'])
    client_hostname = data['client_hostname']
    db = get_db()
    if not db.clients.find_one({'hostname': client_hostname}):
        raise Exception('Attempt to create pipe for invalid client {}'.format(
            client_hostname))
    key = data['encryption_key']
    iv = data['encryption_iv']
    uuid = uuid4().hex
    with redis_collections.SyncableDefaultDict(
            dict,
            redis=redis_encryptors_db,
            key='encryptors') as encryptors:
        encryptors[uuid]['server'] = {'send': {'k': key, 'i': iv},
                                      'receive': {'k': key, 'i': iv}}
    with redis_collections.SyncableDict(
            redis=redis_pipes_db,
            key="pipes") as pipes:
        pipes[uuid] = {
            'client_opened': False,
            'client_closed': False,
            'server_closed': False,
            'client_to_server': b'',
            'server_to_client': b'',
            'created': time.time(),
            'activity': None,
            'client_hostname': client_hostname,
        }
    log.debug('Created pipe {}', uuid)
    return json.dumps({'pipe_id': uuid})


@app.route('/PenguinDome/v1/server_pipe/client/open', methods=('POST',))
@app.route('/penguindome/v1/server_pipe/client/open', methods=('POST',))
@verify_signature
def pipe_open():
    data = json.loads(request.form['data'])
    uuid = data['pipe_id']
    with redis_collections.SyncableDict(
            redis=redis_pipes_db,
            key="pipes") as pipes:
        if uuid not in pipes:
            log.error('Attempt to open nonexistent pipe {}', uuid)
            abort(404)
        key = data['encryption_key']
        iv = data['encryption_iv']

        with redis_collections.SyncableDefaultDict(
                dict,
                redis=redis_encryptors_db,
                key='encryptors') as encryptors:
            encryptors[uuid]['client'] = {'send': {'k': key, 'i': iv},
                                          'receive': {'k': key, 'i': iv}}
        try:
            pipe = pipes[uuid]
            if pipe['client_opened']:
                raise Exception('Attempt to open already opened pipe')
            pipe['client_opened'] = True
        finally:
            # DictProxy doesn't detect updates to nested dicts.
            pipes[uuid] = pipe

    return json.dumps({'status': 'ok'})


# I didnt like the idea of logging, even in one direction,
# ie. what if someone cat's a private key or something?
'''
class PipeLogger(object):
    pending = {}
    directions = {'send': '<<<', 'receive': '>>>'}

    # Can contain 'send' and/or 'receive'. I'm still up in the air about
    # whether it's necessary to log data received from the server end of the
    # pipe. I think it's not, because we're most concerned about exfiltration
    # of data from the client, and because given the only thing we're currently
    # using pipes for right now, i.e., remote shells, most everything the admin
    # types on the server will be echo'd back by the client's terminal.
    # Therefore, since this is where my thinking is right now, I'm only logging
    # data received from the client for the time being.
    enabled = ('receive',)

    @classmethod
    def get(cls, uuid, direction, data):
        if uuid not in cls.pending:
            cls.pending[uuid] = {
                d: {'data': b'',
                    'last': time.time(),
                    'masking': 0,
                    'prefix': p}
                for d, p in cls.directions.items()}
            with redis_collections.SyncableDict(
                    redis=redis_pipes_db,
                    key="pipes") as pipes:
                cls.pending[uuid]['hostname'] = pipes[uuid]['client_hostname']
        cls.pending[uuid][direction]['data'] += data
        return cls.pending[uuid]

    @classmethod
    def split_lines(cls, pending):
        for sep in (b'\r\n', b'\n', b'\r'):
            if sep in pending['data']:
                pending['lines'] = pending['data'].split(sep)
                pending['data'] = pending['lines'].pop()
                return True
        return False

    @classmethod
    def log(cls, uuid, direction, data):
        pending = cls.get(uuid, direction, data)
        if cls.split_lines(pending[direction]):
            cls.emit_lines(pending, direction)
        if not pending[direction]['data']:
            return
        # Arbitrary: Log if there are more than 80 characters or it's been more
        # than 30 seconds since we started accumulating the current line of
        # data.
        if len(pending[direction]['data']) > 80 or \
           time.time() - pending[direction]['last'] > 30:
            pending[direction]['lines'] = [pending[direction]['data']]
            pending[direction]['data'] = b''
            cls.emit_lines(pending, direction)

    @classmethod
    def emit_lines(cls, pending, direction):
        lines = pending[direction].pop('lines', [])
        for line in lines:
            # If the word "password" appears in the output from the client,
            # then mask the next two lines sent from the server.
            if direction == 'receive' and re.search(b'password', line, re.I) \
               and 'send' in cls.enabled:
                log.info('pipelog[{}] {}(Masking next line as potential '
                         'password)', pending['hostname'],
                         pending['send']['prefix'])
                pending['send']['masking'] += 1
            try:
                line = line.decode()
            except Exception:
                line = str(line)
            if pending[direction]['masking']:
                pending[direction]['masking'] -= 1
                line = re.sub(r'.', '.', line)
            if direction in cls.enabled:
                log.info('pipelog[{}] {}{}', pending['hostname'],
                         pending[direction]['prefix'], line)
            pending[direction]['last'] = time.time()

    @classmethod
    def finish(cls, uuid):
        try:
            pending = cls.pending[uuid]
        except KeyError:
            return
        for direction in cls.directions.keys():
            if cls.split_lines(pending[direction]):
                if pending[direction]['data']:
                    pending[direction]['lines'].append(
                        pending[direction]['data'])
            elif pending[direction]['data']:
                pending[direction]['lines'] = [pending[direction]['data']]
            if 'lines' in pending[direction]:
                cls.emit_lines(pending, direction)
        del cls.pending[uuid]
'''


@app.route('/PenguinDome/v1/server_pipe/<peer_type>/send', methods=('POST',))
@app.route('/penguindome/v1/server_pipe/<peer_type>/send', methods=('POST',))
@flush_content
def pipe_send(peer_type):
    if peer_type not in ('client', 'server'):
        raise Exception('Invalid peer type "{}"'.format(peer_type))
    data = json.loads(request.form['data'])
    uuid = data['pipe_id']
    with redis_collections.SyncableDict(
            redis=redis_pipes_db,
            key="pipes") as pipes:
        if uuid not in pipes:
            log.error('Attempt to send to nonexistent pipe {}', uuid)
            abort(404)

        pipe = pipes[uuid]
        pipe['activity'] = time.time()
        try:
            other_peer_type = 'server' if peer_type == 'client' else 'client'
            closed_field = other_peer_type + '_closed'
            if pipe[closed_field]:
                return json.dumps({'eof': True})
            data_field = peer_type + '_to_' + other_peer_type
            encoded_data = data['data']
            encrypted_data = b64decode(encoded_data)

            with redis_collections.SyncableDefaultDict(
                    dict,
                    redis=redis_encryptors_db,
                    key='encryptors') as encryptors:
                encryptor = encryptors[uuid][peer_type]['send']
            decrypted_data = Encryptor(
                encryptor['k'],
                encryptor['i']
            ).decrypt(encrypted_data)
            pipe[data_field] += decrypted_data
            if peer_type == 'server':
                # PipeLogger.log(uuid, 'send', decrypted_data)
                pass
            return json.dumps({'status': 'ok'})
        finally:
            # DictProxy doesn't detect updates to nested dicts.
            pipes[uuid] = pipe


@app.route('/PenguinDome/v1/server_pipe/<peer_type>/receive',
           methods=('POST',))
@app.route('/penguindome/v1/server_pipe/<peer_type>/receive',
           methods=('POST',))
@flush_content
def pipe_receive(peer_type):
    if peer_type not in ('client', 'server'):
        raise Exception('Invalid peer type "{}"'.format(peer_type))
    data = json.loads(request.form['data'])
    uuid = data['pipe_id']
    with redis_collections.SyncableDict(redis=redis_pipes_db,
                                        key="pipes") as pipes:
        if uuid not in pipes:
            log.error('Attempt to receive from nonexistent pipe {}', uuid)
            abort(404)

        pipe = pipes[uuid]
        pipe['activity'] = time.time()
        try:
            other_peer_type = 'server' if peer_type == 'client' else 'client'
            data_field = other_peer_type + '_to_' + peer_type
            if pipe[data_field]:
                with redis_collections.SyncableDefaultDict(
                        dict, redis=redis_encryptors_db,
                        key='encryptors') as encryptors:
                    encryptor = encryptors[uuid][peer_type]['receive']
                encrypted_data = Encryptor(
                    encryptor['k'],
                    encryptor['i']
                ).encrypt(pipe[data_field])
                encoded_data = b64encode(encrypted_data).decode('utf8')
                ret = json.dumps({'data': encoded_data})
                if peer_type == 'server':
                    # PipeLogger.log(uuid, 'receive', pipe[data_field])
                    pass
                pipe[data_field] = b''
                return ret
            closed_field = other_peer_type + '_closed'
            if pipe[closed_field]:
                return json.dumps({'eof': True})
            return json.dumps({'status': 'ok'})
        finally:
            # DictProxy doesn't detect updates to nested dicts.
            pipes[uuid] = pipe


@app.route('/PenguinDome/v1/server_pipe/<peer_type>/close', methods=('POST',))
@app.route('/penguindome/v1/server_pipe/<peer_type>/close', methods=('POST',))
@verify_signature
def pipe_close(peer_type):
    if peer_type not in ('client', 'server'):
        raise Exception('Invalid peer type "{}"'.format(peer_type))
    data = json.loads(request.form['data'])
    uuid = data['pipe_id']
    with redis_collections.SyncableDict(
            redis=redis_pipes_db, key="pipes") as pipes:
        if uuid not in pipes:
            log.error('Attempt to close nonexistent pipe {}', uuid)
            abort(404)

        pipe = pipes[uuid]
        try:
            other_peer_type = 'server' if peer_type == 'client' else 'client'
            closed_field = peer_type + '_closed'
            other_closed_field = other_peer_type + '_closed'
            pipe[closed_field] = True
            client_opened = peer_type == 'client' or pipe['client_opened']
            if not client_opened or pipe[other_closed_field]:
                del pipes[uuid]
                with redis_collections.SyncableDefaultDict(
                        dict,
                        redis=redis_encryptors_db,
                        key='encryptors') as encryptors:
                    encryptors.pop(uuid, None)
                    if peer_type == 'server':
                        # PipeLogger.finish(uuid)
                        pass
            return json.dumps({'status': 'ok'})
        finally:
            # DictProxy doesn't detect updates to nested dicts.
            if uuid in pipes:  # i.e., it wasn't deleted above
                pipes[uuid] = pipe


def clean_up_encryptors(*args):
    with redis_collections.SyncableDefaultDict(
            dict, redis=redis_encryptors_db, key='encryptors') as encryptors:
        for uuid in list(encryptors.keys()):
            with redis_collections.SyncableDict(redis=redis_pipes_db,
                                                key="pipes") as pipes:
                if uuid not in pipes:
                    del encryptors[uuid]
    newThread = threading.Timer(60 * 60, clean_up_encryptors)
    newThread.daemon = True
    newThread.start()


def startDebugServer(pipes_arg, local_only=False):
    global log

    # Get the ports to listen on
    port = get_server_setting('port')
    local_port = get_server_setting('local_port')

    # TODO: Not too sure what to do with this... i think dict logger
    # would probably be the most configurable?

    # Logbook will handle all logging, via the root handler installed by
    # `get_logger` when it alls `logbook.compat.redirect_logging()`.
    del app.logger.handlers[:]
    app.logger.propagate = True

    children = {}

    def sigint_handler(*args):
        for p in children.values():
            try:
                os.kill(p.pid, signal.SIGKILL)
            except Exception:
                pass

    if local_only:
        p = Process(target=app.run, args=("127.0.0.1", local_port))
        p.start()
        children[local_port] = p
    else:
        p = Process(target=app.run, args=("0.0.0.0", port))
        p.start()
        children[port] = p

    # check for errors
    time.sleep(1)
    problems = False
    for port in children.keys():
        if not children[port].is_alive():
            log.error('Child process for port {} died on startup. Maybe '
                      'its port is in use?', port)
            problems = True
    if problems:
        sigint_handler()
        log.error('Exiting because one or more servers failed to start up')
        sys.exit(1)

    signal.signal(signal.SIGINT, sigint_handler)

    for p in children.values():
        p.join()


def prepare_database():
    db = get_db()

    db.client_parameters.create_indexes([
        IndexModel([('hostname', ASCENDING),
                    ('parameter', ASCENDING)]),
        IndexModel([('parameter', ASCENDING)])])
    db.clients.create_indexes([
        IndexModel([('hostname', ASCENDING)],
                   unique=True),
        IndexModel([('suspended', ASCENDING)])])
    db.issues.create_indexes([IndexModel([('hostname', ASCENDING),
                                          ('name', ASCENDING),
                                          ('closed_at', ASCENDING),
                                          ('unsnooze_at', ASCENDING)]),
                              IndexModel([('closed_at', ASCENDING),
                                          ('unsnooze_at', ASCENDING)]),
                              IndexModel([('hostname', ASCENDING),
                                          ('closed_at', ASCENDING),
                                          ('unsnooze_at', ASCENDING)]),
                              IndexModel([('name', ASCENDING),
                                          ('closed_at', ASCENDING),
                                          ('unsnooze_at', ASCENDING)]),
                              IndexModel([('hostname', ASCENDING),
                                          ('suspended', ASCENDING)])])
    db.patches.create_indexes([IndexModel([('pending_hosts', ASCENDING)]),
                               IndexModel([('files.path', ASCENDING)])])


def clean_up_pipes(*args):
    now = time.time()
    with redis_collections.SyncableDict(
            redis=redis_pipes_db, key="pipes") as pipes:
        for uuid in list(pipes.keys()):
            active = pipes[uuid]['activity'] or pipes[uuid]['created']
            if now - active > 60 * 60:  # 1 hour
                del pipes[uuid]
    newThread = threading.Timer(60 * 60, clean_up_pipes)
    newThread.daemon = True
    newThread.start()


@app.before_first_request
def serverInit():
    # Keep this for when we run locally for debugging.
    # The server startup will be done through nginx+gunicorn
    global log

    log = get_logger('server')

    app.config['deprecated_port'] = get_port_setting(
        get_server_setting('port'), 'deprecated', False
    )

    prepare_database()
    clean_up_encryptors()

    clean_up_pipes()


if __name__ == '__main__':
    startDebugServer(serverInit(), local_only=True)
