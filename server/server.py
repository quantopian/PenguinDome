#!/usr/bin/env python3

from bson import ObjectId
import datetime
from flask import Flask, request, Response
from functools import wraps
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from multiprocessing import Process
import os
from passlib.hash import pbkdf2_sha256
from pymongo import ASCENDING
import signal
import tempfile

from qlmdm import (
    top_dir,
    set_gpg,
    releases_dir,
    gpg_command,
)
import qlmdm.json as json
from qlmdm.server import (
    get_logger,
    get_setting as get_server_setting,
    get_port_setting,
    get_db,
    open_issue,
    close_issue,
    encrypt_document,
    audit_trail_write,
)

log = get_logger('server')

os.chdir(top_dir)
set_gpg('server')

app = Flask(__name__)


def log_deprecated_port(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            hostname = json.loads(request.form['data'])['hostname']
            ok = True
        except:
            log.error('Failed to parse request data')
            ok = False
            hostname = request.remote_addr
        if app.config['deprecated_port']:
            log.warn('Host {} connected to deprecated port', hostname)
            if ok:
                open_issue(hostname, 'deprecated-port')
        else:
            if ok:
                close_issue(hostname, 'deprecated-port')
        return f(*args, **kwargs)
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
    except:
        try:
            remote_addr = IPv6Address(request.remote_addr)
        except:
            log.debug("No auth: can't parse IP address {}",
                      request.remote_addr)
            return False
    for range_string in auth_info:
        try:
            ip_range = IPv4Network(range_string)
        except:
            try:
                ip_range = IPv6Network(range_string)
            except:
                raise Exception('Invalid address range {} in {}'.format(
                    range_string, auth_name))
        if remote_addr in ip_range:
            log.debug('Auth success: {} is in {}', remote_addr, ip_range)
            return True
    log.debug('No auth: no matching IP ranges for {} in {}', remote_addr,
              auth_name)


def check_password(auth_name):
    auth_info = get_server_setting(auth_name + ':passwords')
    if not auth_info:
        log.debug('No auth: no passwords configured in {}', auth_name)
        return False
    if not request.authorization:
        log.debug('No auth: no username specified in request')
        return False
    try:
        password_hash = auth_info[request.authorization.username]
    except KeyError:
        # N.B. One does not log usernames from authentication requests, in
        # case the user accidentally typed the password in the username field,
        # so that one doesn't accidentally log passwords.
        log.debug('No auth: specified username not in {}', auth_name)
        return False
    if not pbkdf2_sha256.verify(request.authorization.password, password_hash):
        # It's OK to log the username here, since we've already confirmed that
        # it's a valid username, not a password.
        log.debug('No auth: incorrect password for {} in {}',
                  request.authorization.username, auth_name)
        return False
    return True


def require_httpauth(auth_name, mandatory=True):
    """Authenticate a request

    `auth_setting` is the server configuration setting containing the
    authentication information for the request. If it's empty and `mandatory`
    is True, an exception is raised; otherwise, the request is allowed to
    proceed (i.e., whether an endpoint with optional authentication has it is
    enforced by the configuration file).

    The authentication information can contain the subkey `passwords` and/or
    `ipranges`.

    `ipranges` is a list of IP ranges. If the remote address of the request
    falls in any of the specified ranges, then the authentication succeeds with
    no need for a username and password.

    `passwords` is a dictionary of username / pbkdf2_sha256 hashes. If the
    username specified by the user matches any of the usernames in the
    dictionary, then the authentication succeeds if the password matches the
    stored hash.
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not (no_auth_needed(auth_name, mandatory=mandatory) or
                    check_ip_auth(auth_name) or check_password(auth_name)):
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
            try:
                data = request.form['data']
            except:
                raise Exception('Malformed request: no data')
            try:
                signature = request.form['signature']
            except:
                raise Exception('Malformed request: no signature')
            with tempfile.NamedTemporaryFile('w+') as data_file, \
                    tempfile.NamedTemporaryFile('w+') as signature_file:
                data_file.write(data)
                data_file.flush()
                signature_file.write(signature)
                signature_file.flush()
                try:
                    gpg_command('--verify', signature_file.name,
                                data_file.name)
                except:
                    raise Exception('Bad signature')
        except:
            log.exception()
            raise
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


@app.route('/qlmdm/v1/submit', methods=('POST',))
@verify_signature
@log_deprecated_port
def submit():
    db = get_db()
    which = []
    now = datetime.datetime.utcnow()
    data = json.loads(request.form['data'])
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


@app.route('/qlmdm/v1/update', methods=('POST',))
@verify_signature
@log_deprecated_port
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


@app.route('/qlmdm/v1/acknowledge_patch', methods=('POST',))
@verify_signature
@log_deprecated_port
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


@app.route('/qlmdm/v1/download_release', methods=('GET',))
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


def startServer(port):
    app.config['deprecated_port'] = get_port_setting(port, 'deprecated', False)

    # Logbook will handle all logging, via the root handler installed by
    # `get_logger` when it alls `logbook.compat.redirect_logging()`.
    del app.logger.handlers[:]
    app.logger.propagate = True

    kwargs = {
        'host': '0.0.0.0',
        'port': port,
        'threaded': get_port_setting(port, 'threaded', True),
    }

    ssl_certificate = get_port_setting(port, 'ssl:certificate', None)
    ssl_key = get_port_setting(port, 'ssl:key', None)
    ssl_enabled = get_port_setting(port, 'ssl:enabled', bool(ssl_certificate))
    if bool(ssl_certificate) + bool(ssl_key) == 1:
        raise Exception('You must specify both certificate and key for SSL!')

    if ssl_enabled:
        kwargs['ssl_context'] = (ssl_certificate, ssl_key)

    app.run(**kwargs)


def prepare_database():
    db = get_db()

    db.clients.create_index([('hostname', ASCENDING)], unique=True)


def main():
    ports = None
    port = get_server_setting('port')
    if isinstance(port, int):
        ports = [port]
    elif isinstance(port, dict):
        ports = list(port.keys())
    if len(ports) == 1:
        port = ports.pop()

    prepare_database()

    if ports:
        children = []
        for port in ports:
            p = Process(target=startServer, args=(port,))
            p.daemon = True
            p.start()
            children.append(p)

        def sigint_handler(*args):
            for p in children:
                os.kill(p.pid, signal.SIGINT)

        signal.signal(signal.SIGINT, sigint_handler)
        for p in children:
            p.join()
    else:
        startServer(port)


if __name__ == '__main__':
    main()
