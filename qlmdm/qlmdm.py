import json
import logbook
import os
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
settingses = {}
var_dir = os.path.join(top_dir, 'var')
releases_dir = os.path.join(var_dir, 'client_releases')
collected_dir = os.path.join(var_dir, 'collected')
release_file = os.path.join('client', 'release.txt')
signatures_dir = 'signatures'


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


def load_settings(which):
    if which in settingses:
        return settingses[which]

    settings_file = os.path.join(top_dir, which, 'settings.yml')
    if os.path.exists(settings_file):
        settings = yaml.load(open(settings_file))
        settings['loaded'] = True
    else:
        settings = {'loaded': False}

    defaults_file = os.path.join(top_dir, which, 'default-settings.yml')
    settings['defaults'] = yaml.load(open(defaults_file))

    if 'server_url' in settings:
        settings['server_url'] = re.sub(r'/+$', '', settings['server_url'])

    settingses[which] = settings

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
        subprocess.check_output(('gpg', '--armor', '--batch', '--yes',
                                 '--detach-sign', '-o', signature_file.name,
                                 data_path), stderr=subprocess.STDOUT)
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
    return signature_file[len(top_dir)+1:]


def sign_data(data):
    with NamedTemporaryFile() as data_file, \
         NamedTemporaryFile() as signature_file:
        data_file.write(data)
        data_file.flush()
        subprocess.check_output(('gpg', '--yes', '--batch', '--detach-sig',
                                 '-o', signature_file.name, data_file.name))
        return signature_file.read()


def get_logger(setting_getter, name):
    handler_name = setting_getter('logging:handler').lower()
    handler_name += 'handler'
    handler_name = next(d for d in dir(logbook) if d.lower() == handler_name)
    handler = logbook.__dict__[handler_name]
    kwargs = {}
    if handler_name == 'SyslogHandler':
        kwargs['facility'] = setting_getter('logging:facility')
    for kwarg, value in ((a, b) for a, b in setting_getter('logging').items()
                         if a not in ('handler', 'level', 'facility')):
        kwargs[kwarg] = value
    handler(**kwargs).push_application()
    level = setting_getter('logging:level')
    level = logbook.__dict__[level.upper()]
    logbook.compat.redirect_logging()
    return logbook.Logger('qlmdm-' + name, level=level)
