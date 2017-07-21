from functools import partial
import json
import os
import requests
from tempfile import NamedTemporaryFile

from qlmdm import (
    load_settings,
    get_setting as main_get_setting,
    set_setting as main_set_setting,
    get_logger as main_get_logger,
    save_settings as main_save_settings,
    get_selectors as main_get_selectors,
    encrypt_document as main_encrypt_document,
    client_gpg_version,
    gpg_command as main_gpg_command,
    top_dir,
)

gpg_command = partial(main_gpg_command, minimum_version=client_gpg_version)


def get_setting(setting, default=None, check_defaults=True):
    return main_get_setting(load_settings('client'), setting, default,
                            check_defaults)


def set_setting(setting, value):
    return main_set_setting(load_settings('client'), setting, value)


def save_settings():
    main_save_settings('client')


def get_logger(name):
    return main_get_logger(get_setting, name)


def get_selectors():
    return main_get_selectors(get_setting)


def encrypt_document(doc, log=None):
    return main_encrypt_document(get_setting, doc, log=log)


def server_request(cmd, data=None, data_path=None):
    server_url = get_setting('server_url')
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
        'timeout': 30,
    }
    ca_path = get_setting('ssl:ca_path')
    if ca_path:
        if not ca_path.startswith('/'):
            ca_path = os.path.join(top_dir, ca_path)
        kwargs['verify'] = ca_path
    response = requests.post('{}{}'.format(server_url, cmd), **kwargs)
    response.raise_for_status()
    return response
