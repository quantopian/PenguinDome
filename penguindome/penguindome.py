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

from base64 import b64encode
from collections import namedtuple, OrderedDict
import datetime
from packaging.version import Version
import fcntl
import fnmatch
import glob
from hashlib import md5
from itertools import chain
import logbook
import os
import pickle
import re
import socket
import stat
from stopit import ThreadingTimeout
import subprocess
from tempfile import NamedTemporaryFile
import yaml

import penguindome.json as json

top_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
gpg_private_dir = os.path.join('server', 'keyring')
gpg_public_dir = os.path.join('client', 'keyring')
gpg_private_home = os.path.join(top_dir, gpg_private_dir)
gpg_public_home = os.path.join(top_dir, gpg_public_dir)
release_subdirs = ('client', 'penguindome')
settingses = {}
var_dir = os.path.join(top_dir, 'var')
releases_dir = os.path.join(var_dir, 'client_releases')
collected_dir = os.path.join(var_dir, 'collected')
release_file = os.path.join('client', 'release.txt')
plugins_dir = os.path.join('client', 'plugins')
commands_dir = os.path.join('client', 'commands')
signatures_dir = 'signatures'
gpg_mode = None
gpg_exe = None
got_logger = None
client_gpg_version = '2.1.11'
server_pipe_log_filter_re = re.compile(
    r'POST.*/server_pipe/.*/(?:send|receive).* 200 ')
gpg_user_ids = {
    'client': 'penguindome-client',
    'server': 'penguindome-server',
}

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
            relative_path = path[len(top_dir) + 1:]
            if fnmatch.fnmatch(relative_path, '*/keyring/reader_*.status'):
                continue
            if fnmatch.fnmatch(relative_path, '*/keyring/sshcontrol'):
                continue
            if relative_path == 'client/plugins/__init__.py':
                continue
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


def gpg_command(*cmd, with_user_id=False, with_trustdb=False, quiet=True,
                minimum_version='2.1.15', log=None):
    global gpg_exe, gpg_exe

    if not gpg_mode:
        raise Exception('Attempt to use GPG before setting mode')
    if not gpg_exe:
        try:
            output = subprocess.check_output(
                ('gpg2', '--version'),
                stderr=subprocess.STDOUT).decode('utf8')
        except Exception:
            output = subprocess.check_output(
                ('gpg', '--version'),
                stderr=subprocess.STDOUT).decode('utf8')
            gpg_exe = 'gpg'
        else:
            gpg_exe = 'gpg2'
        match = re.search(r'^gpg \(GnuPG\) (\d+(?:\.\d+(?:\.\d+)?)?)', output,
                          re.MULTILINE)
        if not match:
            raise Exception('Could not determine GnuPG version in output:\n{}'.
                            format(output))
        if Version(match.group(1)) < Version(minimum_version):
            raise Exception('GnuPG version {} or newer is required. '
                            'You have version {}.'.format(
                                minimum_version, match.group(1)))

    if with_trustdb:
        trustdb_args = ()
    else:
        trustdb_args = ('--trust-model', 'always')

    if with_user_id:
        user_id_args = ('-u', gpg_user_ids[gpg_mode])
    else:
        user_id_args = ()

    if quiet:
        quiet_args = ('--quiet',)
    else:
        quiet_args = ()

    cmd = tuple(chain((gpg_exe, '--batch', '--yes'), quiet_args, trustdb_args,
                      user_id_args, cmd))
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).\
            decode('utf8')
    except subprocess.CalledProcessError as e:
        if log:
            log.exception('Gpg command {} failed. Output:\n{}'.format(
                cmd, e.output.decode('utf8')))
        raise


def load_settings(which):
    settings_file = os.path.join(top_dir, which, 'settings.yml')
    try:
        mtime = os.stat(settings_file).st_mtime
    except Exception:
        mtime = 0

    if which in settingses and mtime <= settingses[which]['mtime']:
        return settingses[which]['settings']

    if os.path.exists(settings_file):
        settings = yaml.safe_load(open(settings_file))
        settings['loaded'] = True
    else:
        settings = {'loaded': False}

    defaults_file = os.path.join(top_dir, which, 'default-settings.yml')
    settings['defaults'] = yaml.safe_load(open(defaults_file))

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
        defaults = settings.get('defaults', {})
    for key in setting.split(':'):
        try:
            settings = settings[key]
        except Exception:
            if check_defaults:
                return get_setting(defaults, setting, default,
                                   check_defaults=False)
            return default
    return settings


def set_setting(settings, setting, value):
    keys = setting.split(':')
    subsettings = settings
    while len(keys) > 1:
        if keys[0] not in subsettings:
            subsettings[keys[0]] = {}
        subsettings = subsettings[keys[0]]
        keys.pop(0)
    if value is None:
        subsettings.pop(keys[0], None)
        if get_setting(settings, setting):
            # It has a default, so we need to store an override.
            subsettings[keys[0]] = None
    else:
        subsettings[keys[0]] = value


def verify_signature(file, top_dir=top_dir, raise_errors=False):
    signature_file = os.path.join(top_dir, signatures_dir, file + '.sig')
    file = os.path.join(top_dir, file)
    try:
        gpg_command('--verify', signature_file, file,
                    minimum_version=client_gpg_version)
    except subprocess.CalledProcessError:
        if raise_errors:
            raise
        return None
    return signature_file[len(top_dir) + 1:]


class FlockFileLock(object):
    def __init__(self, path):
        self.path = path
        self.file = None

    def acquire(self):
        """Returns True if file has been changed, False otherwise"""
        ret = False
        while True:
            if not self.file:
                self.file = open(self.path, 'a')
                self.fstatd = os.fstat(self.file.fileno())
                ret = True
            try:
                fcntl.flock(self.file, fcntl.LOCK_EX)
            except Exception:
                try:
                    self.file.close()
                except Exception:
                    pass
                self.file = None
                raise
            try:
                statd = os.stat(self.path)
            except FileNotFoundError:
                try:
                    self.file.close()
                except Exception:
                    pass
                self.file = None
                continue
            except Exception:
                try:
                    self.file.close()
                except Exception:
                    pass
                self.file = None
                raise
            if self.fstatd[stat.ST_DEV] == statd[stat.ST_DEV] and \
               self.fstatd[stat.ST_INO] == statd[stat.ST_INO]:
                return ret
            self.file.close()
            self.file = None

    def release(self):
        if not self.file:
            return
        fcntl.flock(self.file, fcntl.LOCK_UN)


class FlockRotatingFileHandler(logbook.FileHandler):
    def __init__(self, filename, encoding='utf-8', level=logbook.NOTSET,
                 format_string=None, delay=False, max_size=1024 * 1024,
                 backup_count=5, filter=None, bubble=False):
        self.max_size = max_size
        self.backup_count = backup_count
        super(FlockRotatingFileHandler, self).__init__(
            filename, encoding=encoding, level=level,
            format_string=format_string, delay=delay, filter=filter,
            bubble=bubble)
        self.flock = FlockFileLock(filename)

    def should_rollover(self):
        self.stream.seek(0, 2)
        return self.stream.tell() >= self.max_size

    def perform_rollover(self):
        self.stream.close()
        for x in range(self.backup_count - 1, 0, -1):
            src = '%s.%d' % (self._filename, x)
            dst = '%s.%d' % (self._filename, x + 1)
            try:
                os.rename(src, dst)
            except FileNotFoundError:
                pass
        os.rename(self._filename, self._filename + '.1')
        self._open('a')

    def emit(self, record):
        try:
            self.lock.acquire()
            changed = self.flock.acquire()
            if changed:
                self.flush()
                if self.stream:
                    try:
                        self.stream.close()
                    except Exception:
                        pass
                    self.stream = None
                self.ensure_stream_is_open()
            super(FlockRotatingFileHandler, self).emit(record)
            if self.should_rollover():
                self.perform_rollover()
        finally:
            try:
                self.lock.release()
            except Exception:
                pass
            self.flock.release()


def get_logger(setting_getter, name, fail_to_local=False, filter=None):
    global got_logger
    if got_logger:
        # Yes, this means that if you try to change your logging within an
        # application, it won't work. This is intentional. You shouldn't do
        # that.
        return got_logger

    if filter:
        def log_filter(r, h):
            if server_pipe_log_filter_re.search(r.message):
                return False
            return filter(r, h)
    else:
        def log_filter(r, h):
            return not server_pipe_log_filter_re.search(r.message)

    logger_name = 'penguindome-' + name
    file_safe_logger_name = logger_name.replace(os.sep, '_')

    logger = logbook.Logger(logger_name)

    internal_log_dir = os.path.join(var_dir, 'log')
    internal_log_file = os.path.join(
        internal_log_dir, file_safe_logger_name + '.log')

    os.makedirs(internal_log_dir, 0o0700, exist_ok=True)

    # We always do local debug logging, regardless of whether we're also
    # logging elsewhere.
    FlockRotatingFileHandler(
        internal_log_file, bubble=True, filter=log_filter).push_application()

    handler_name = setting_getter('logging:handler')
    if handler_name:
        handler_name = handler_name.lower()
        handler_name += 'handler'
        handler_name = next(d for d in dir(logbook)
                            if d.lower() == handler_name)
        handler = logbook.__dict__[handler_name]
        kwargs = {'bubble': True, 'filter': log_filter}
        level = setting_getter('logging:level')
        kwargs['level'] = logbook.__dict__[level.upper()]
        if handler_name == 'SyslogHandler':
            kwargs['facility'] = setting_getter('logging:syslog:facility')
            hostname = setting_getter('logging:syslog:host')
            if hostname:
                port = setting_getter('logging:syslog:port')
                try:
                    addrinfo = socket.getaddrinfo(
                        hostname, port, socket.AF_INET, socket.SOCK_STREAM)[0]
                except Exception:
                    if not fail_to_local:
                        raise
                    logger.warn('Failed to resolve {}:{}, falling back to '
                                'local-only logging', hostname, port)
                    handler = None
                else:
                    kwargs['socktype'] = addrinfo[1]
                    kwargs['address'] = addrinfo[4]

        if handler:
            if fail_to_local:
                try:
                    with ThreadingTimeout(5, swallow_exc=False):
                        handler = handler(**kwargs)
                except Exception:
                    logger.warn('Failed to create {}, falling back to '
                                'local-only logging', handler_name)
                else:
                    handler.push_application()
            else:
                handler(**kwargs).push_application()

    logbook.compat.redirect_logging()
    got_logger = logger
    return got_logger


def get_selectors(getter):
    return tuple(SelectorVariants(s, s.replace('.', ':'), s + '-encrypted',
                                  s.replace('.', ':') + '-encrypted')
                 for s in getter('secret_keeping:selectors', []))


def orderify(obj):
    """Convert dicts (recursively) to ordered dicts with sorted keys"""

    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, dict):
                obj[key] = orderify(value)
                continue
            if isinstance(value, (tuple, list)):
                obj[key] = orderify(value)
        obj = OrderedDict((key, obj[key]) for key in sorted(obj.keys()))
    elif isinstance(obj, (tuple, list)):
        obj = type(obj)(sorted((orderify(v) for v in obj),
                               key=str))

    return obj


def encrypt_document(getter, doc, log=None, selectors=None):
    if not getter('secret_keeping:enabled'):
        return doc, None
    key_id = getter('secret_keeping:key_id')
    if selectors is None:
        selectors = get_selectors(getter)
    update = {'$unset': {}, '$set': {}}
    for s in selectors:
        decrypted_data = get_setting(
            doc, s.plain_mem, check_defaults=False)
        if not decrypted_data:
            continue
        # This assures that the same decrypted data will always end up with the
        # same md5 hash by ensuring that the data are always encoded in the
        # same order.
        if isinstance(decrypted_data, dict):
            decrypted_data = orderify(decrypted_data)
        decrypted_data = json.dumps(decrypted_data).encode('utf-8')
        with NamedTemporaryFile('w+b') as unencrypted_file, \
                NamedTemporaryFile('w+b') as encrypted_file:
            unencrypted_file.write(decrypted_data)
            unencrypted_file.flush()
            try:
                gpg_command('--encrypt', '--recipient', key_id, '-o',
                            encrypted_file.name, unencrypted_file.name,
                            minimum_version=client_gpg_version)
            except subprocess.CalledProcessError as e:
                if log:
                    log.error('Gpg failed to encrypt. Output:\n{}',
                              e.output.decode('utf8'))
                raise
            encrypted_file.seek(0)
            encrypted_data = {
                'hash': md5(decrypted_data).hexdigest(),
                'data': b64encode(encrypted_file.read()).decode('utf8')}
        if s.plain_mongo != s.enc_mongo:
            update['$unset'][s.plain_mongo] = True
        update['$set'][s.enc_mongo] = encrypted_data
        set_setting(doc, s.plain_mem, None)
        set_setting(doc, s.enc_mem, encrypted_data)
    if update['$set']:
        if not update['$unset']:
            update.pop('$unset')
        return doc, update
    return doc, None


def cached_data(key, data=None, add_timestamp=False, check_logged_in=False,
                raise_exception=True):
    """Return or save cached data for the specified key

    If data is None and there is no cached data for the specified key, raises
    FileNotFoundError unless raise_exception is False in which case just
    returns None.

    If add_timestamp is true, then adds a cached_at timestamp to data (which
    must be a dict or dict-like object) before saving it.

    If check_logged_in is true, then checks if any users are currently logged
    in before saving or returning the data, and if not, then assumes that data
    is None even if it actually isn't.
    """

    if os.sep in key:
        raise Exception('Cache keys cannot have {} in them'.format(os.sep))

    cache_file = os.path.join(var_dir, 'data_cache', key)

    if check_logged_in and subprocess.check_output('who') == b'':
        # No one is logged in
        data = None

    if data is None:
        try:
            return pickle.load(open(cache_file, 'rb'))
        except FileNotFoundError:
            if raise_exception:
                raise
            return None

    os.makedirs(os.path.dirname(cache_file), exist_ok=True)

    if add_timestamp and isinstance(data, dict):
        save_data = data.copy()
        save_data['cached_at'] = datetime.datetime.now(datetime.timezone.utc)
    else:
        save_data = data

    pickle.dump(save_data, open(cache_file, 'wb'))
    return data
