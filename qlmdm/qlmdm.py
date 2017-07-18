from base64 import b64encode
from bson import BSON
from collections import namedtuple
import glob
from itertools import chain
import json
import logbook
import os
import re
import requests
import socket
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
settingses = {}
var_dir = os.path.join(top_dir, 'var')
releases_dir = os.path.join(var_dir, 'client_releases')
collected_dir = os.path.join(var_dir, 'collected')
release_file = os.path.join('client', 'release.txt')
signatures_dir = 'signatures'
gpg_mode = None
gpg_exe = None
got_logger = None

SelectorVariants = namedtuple(
    'SelectorVariants', ['plain_mongo', 'plain_mem', 'enc_mongo', 'enc_mem'])


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
    global gpg_mode

    if mode == 'server':
        home = gpg_private_home
    elif mode == 'client':
        home = gpg_public_home
    else:
        raise Exception('Internal error: Unrecognized GPG mode {}'.format(
            mode))

    os.environ['GNUPGHOME'] = home
    os.chmod(home, 0o0700)
    # random seed gets corrupted sometimes because we're copying keyring from
    # server to client
    list(map(os.unlink, glob.glob(os.path.join(home, "random_seed*"))))
    gpg_mode = mode


def gpg_command(*cmd, with_trustdb=False, quiet=True):
    global gpg_exe, gpg_exe

    if not gpg_mode:
        raise Exception('Attempt to use GPG before setting mode')
    if not gpg_exe:
        try:
            output = subprocess.check_output(
                ('gpg2', '--version'),
                stderr=subprocess.STDOUT).decode('ascii')
        except:
            output = subprocess.check_output(
                ('gpg', '--version'),
                stderr=subprocess.STDOUT).decode('ascii')
            gpg_exe = 'gpg'
        else:
            gpg_exe = 'gpg2'
        match = re.match(r'^gpg.* ((\d+)(?:\.(\d+)(?:\.(\d+))?)?)', output)
        if not match:
            raise Exception('Could not determine GnuPG version in output:\n{}'.
                            format(output))
        groups = match.groups()
        major = int(groups[1])
        minor = int(groups[2]) if len(groups) > 2 else 0
        patch = int(groups[3]) if len(groups) > 3 else 0
        version = major * 1000000 + minor * 1000 + patch
        if version < 2001015:
            raise Exception('Qlmdm requires GnuPG version 2.1.15 or newer. '
                            'You have version {}.'.format(groups[0]))

    if with_trustdb:
        trustdb_args = ()
    else:
        trustdb_args = ('--trust-model', 'always')

    if quiet:
        quiet_args = ('--quiet',)
    else:
        quiet_args = ()

    cmd = tuple(chain((gpg_exe, '--batch', '--yes'), quiet_args, trustdb_args,
                      cmd))
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).\
        decode('ascii')


def load_settings(which):
    settings_file = os.path.join(top_dir, which, 'settings.yml')
    try:
        mtime = os.stat(settings_file).st_mtime
    except:
        mtime = 0

    if which in settingses and mtime <= settingses[which]['mtime']:
        return settingses[which]['settings']

    if os.path.exists(settings_file):
        settings = yaml.load(open(settings_file))
        settings['loaded'] = True
    else:
        settings = {'loaded': False}

    defaults_file = os.path.join(top_dir, which, 'default-settings.yml')
    settings['defaults'] = yaml.load(open(defaults_file))

    if 'server_url' in settings:
        settings['server_url'] = re.sub(r'/+$', '', settings['server_url'])

    settingses[which] = {'settings': settings, 'mtime': mtime}

    return settings


def save_settings(which):
    settings = load_settings(which)
    bare = settings.copy()
    bare.pop('defaults', None)
    bare.pop('loaded', None)
    yaml.dump(bare, open(os.path.join(top_dir, which, 'settings.yml'), 'w'))
    settings['loaded'] = True


def get_setting(settings, setting, default=None, check_defaults=True):
    """Get a possibly recursive setting from a dictionary

    "settings" is a dictionary. "setting" is a colon-separated list of keys.
    Recurses through "settings" looking for the specified setting, and returns
    the specified default if the setting isn't present and there's no
    preconfigured default setting.
    """
    if check_defaults:
        defaults = settings['defaults']
    for key in setting.split(':'):
        try:
            settings = settings[key]
        except:
            if check_defaults:
                return get_setting(defaults, setting, default,
                                   check_defaults=False)
            return default
    return settings


def set_setting(settings, setting, value):
    keys = setting.split(':')
    while len(keys) > 1:
        if keys[0] not in settings:
            settings[keys[0]] = {}
        settings = settings[keys[0]]
        keys.pop(0)
    if value is not None:
        settings[keys[0]] = value
    else:
        settings.pop(keys[0], None)


def server_request(cmd, data=None, data_path=None):
    server_url = get_setting(load_settings('client'), 'server_url')
    if data and data_path:
        raise Exception('Both data and data_path specified')
    with NamedTemporaryFile('w+') as temp_data_file, \
            NamedTemporaryFile('w+') as signature_file:
        if data:
            data = json.dumps(data)
            temp_data_file.write(data)
            temp_data_file.flush()
            data_path = temp_data_file.name
        else:
            data = open(data_path).read()
        gpg_command('--armor', '--detach-sign', '-o', signature_file.name,
                    data_path)
        signature_file.seek(0)
        post_data = {
            'data': data,
            'signature': signature_file.read(),
        }

    kwargs = {
        'data': post_data,
        'timeout': 60,
    }
    ca_path = get_setting(load_settings('client'), 'ssl:ca_path')
    if ca_path:
        if not ca_path.startswith('/'):
            ca_path = os.path.join(top_dir, ca_path)
        kwargs['verify'] = ca_path
    response = requests.post('{}{}'.format(server_url, cmd), **kwargs)
    response.raise_for_status()
    return response


def verify_signature(file, top_dir=top_dir, raise_errors=False):
    signature_file = os.path.join(top_dir, signatures_dir, file + '.sig')
    file = os.path.join(top_dir, file)
    try:
        gpg_command('--verify', signature_file, file)
    except subprocess.CalledProcessError:
        if raise_errors:
            raise
        return None
    return signature_file[len(top_dir)+1:]


def sign_file(file, top_dir=top_dir):
    signature_file = os.path.join(top_dir, signatures_dir, file + '.sig')
    file = os.path.join(top_dir, file)
    try:
        os.makedirs(os.path.dirname(signature_file))
    except:
        pass
    gpg_command('--detach-sig', '-o', signature_file, file)
    return signature_file[len(top_dir)+1:]


def sign_data(data):
    with NamedTemporaryFile() as data_file, \
         NamedTemporaryFile() as signature_file:
        data_file.write(data)
        data_file.flush()
        gpg_command('--detach-sig', '-o', signature_file.name, data_file.name)
        return signature_file.read()


def get_logger(setting_getter, name):
    global got_logger
    if got_logger:
        # Yes, this means that if you try to change your logging within an
        # application, it won't work. This is intentional. You shouldn't do
        # that.
        return got_logger

    handler_name = setting_getter('logging:handler').lower()
    handler_name += 'handler'
    handler_name = next(d for d in dir(logbook) if d.lower() == handler_name)
    handler = logbook.__dict__[handler_name]
    kwargs = {}
    if handler_name == 'SyslogHandler':
        kwargs['facility'] = setting_getter('logging:syslog:facility')
        hostname = setting_getter('logging:syslog:host')
        if hostname:
            port = setting_getter('logging:syslog:port')
            addrinfo = socket.getaddrinfo(hostname, port, socket.AF_INET,
                                          socket.SOCK_STREAM)[0]
            kwargs['socktype'] = addrinfo[1]
            kwargs['address'] = addrinfo[4]
    handler(**kwargs).push_application()
    level = setting_getter('logging:level')
    level = logbook.__dict__[level.upper()]
    logbook.compat.redirect_logging()
    got_logger = logbook.Logger('qlmdm-' + name, level=level)
    return got_logger


def get_selectors(getter):
    return tuple(SelectorVariants(s, s.replace('.', ':'), s + '-encrypted',
                                  s.replace('.', ':') + '-encrypted')
                 for s in getter('secret_keeping:selectors', []))


def encrypt_document(getter, doc, log=None):
    if not getter('secret_keeping:enabled'):
        return doc, None
    key_id = getter('secret_keeping:key_id')
    selectors = get_selectors(getter)
    update = {'$unset': {}, '$set': {}}
    for s in selectors:
        decrypted_data = get_setting(
            doc, s.plain_mem, check_defaults=False)
        if not decrypted_data:
            continue
        with NamedTemporaryFile('w+b') as unencrypted_file, \
                NamedTemporaryFile('w+b') as encrypted_file:
            unencrypted_file.write(BSON.encode(decrypted_data))
            unencrypted_file.flush()
            try:
                gpg_command('--encrypt', '--recipient', key_id, '-o',
                            encrypted_file.name, unencrypted_file.name)
            except subprocess.CalledProcessError as e:
                if log:
                    log.error('Gpg failed to encrypt. Output:\n{}',
                              e.output.decode('ascii'))
                raise
            encrypted_file.seek(0)
            encrypted_data = b64encode(encrypted_file.read()).decode('ascii')
        update['$unset'][s.plain_mongo] = True
        update['$set'][s.enc_mongo] = encrypted_data
        set_setting(doc, s.plain_mem, None)
        set_setting(doc, s.enc_mem, encrypted_data)
    if update['$unset']:
        return doc, update
    return doc, None
