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

import argparse
from functools import partial
import glob
import logbook
import os
import random
import subprocess
import shutil
import sys
from tempfile import NamedTemporaryFile
from textwrap import dedent

from penguindome import (
    top_dir,
    gpg_private_home,
    gpg_public_home,
    set_gpg,
    gpg_command,
    releases_dir,
)
from penguindome.client import (
    get_setting as get_client_setting,
    set_setting as set_client_setting,
    save_settings as save_client_settings,
)
from penguindome.server import (
    get_setting as get_server_setting,
    set_setting as set_server_setting,
    save_settings as save_server_settings,
)
from penguindome.prompts import (
    get_bool,
    get_int,
    get_string,
    get_string_or_list,
)

os.chdir(top_dir)

os.makedirs(gpg_private_home, 0o700, exist_ok=True)
os.makedirs(gpg_public_home, 0o700, exist_ok=True)

server_user_id = 'penguindome-server'
client_user_id = 'penguindome-client'

entropy_warned = False
get_string_none = partial(get_string, none_ok=True)


def entropy_warning():
    global entropy_warned

    if entropy_warned:
        return
    entropy_warned = True

    print(dedent('''
        If this takes a long time to run, you may want to install haveged or
        some other tool for adding entropy to the kernel.
    '''))


def generate_key(mode, user_id):
    set_gpg(mode)
    try:
        gpg_command('--list-keys', user_id, with_trustdb=True)
    except:
        entropy_warning()
        try:
            gpg_command('--passphrase', '', '--quick-gen-key', user_id,
                        with_trustdb=True)
        except subprocess.CalledProcessError as e:
            sys.exit('PenguinDome requires GnuPG version 2.1 or newer. '
                     'gpg output:\n{}'.format(e.output))


def import_key(to_mode, user_id):
    from_mode = 'client' if to_mode == 'server' else 'server'
    set_gpg(to_mode)
    try:
        gpg_command('--list-keys', user_id)
    except:
        with NamedTemporaryFile() as key_file:
            set_gpg(from_mode)
            gpg_command('--export', '-o', key_file.name, user_id)
            set_gpg(to_mode)
            gpg_command('--import', key_file.name)


def maybe_get_bool(prompt, default, use_default=False):
    if use_default:
        answer = 'yes' if default else 'no'
        print('{} {}'.format(prompt, answer))
        return default
    return get_bool(prompt, default)


def maybe_changed_extended(which, setting, prompter, prompt, empty_ok=False,
                           use_default=False):
    if which == 'server':
        getter = get_server_setting
        setter = set_server_setting
    elif which == 'client':
        getter = get_client_setting
        setter = set_client_setting
    else:
        raise Exception('Invalid which value {}'.format(which))

    default = getter(setting)
    if empty_ok and not default:
        default = ''

    if use_default:
        if isinstance(default, bool):
            answer = 'yes' if default else 'no'
        else:
            answer = default
        print('{} {}'.format(prompt, answer))
        return False

    new = prompter(prompt, default)
    if str(new) != str(default):
        setter(setting, new)
        return True
    return False


def configure_logging(which, maybe_changed):
    if which == 'Server':
        getter = get_server_setting
    elif which == 'Client':
        getter = get_client_setting
    else:
        raise Exception('Invalid which value {}'.format(which))

    which2 = which.lower()
    changed = False

    while True:
        changed |= maybe_changed(
            which2, 'logging:handler', get_string_none, '{} logbook handler '
            '(e.g., stderr, syslog) (empty for none):'.format(which))
        handler = getter('logging:handler')
        if not handler:
            return
        full_handler = handler.lower() + 'handler'
        try:
            next(h for h in logbook.__dict__ if h.lower() == full_handler)
        except StopIteration:
            print('That is not a valid handler.')
            continue
        else:
            break

    while True:
        changed |= maybe_changed(
            which2, 'logging:level', get_string,
            '{} logging level (e.g., debug, info):'.format(which))
        level = getter('logging:level')
        try:
            int(logbook.__dict__[level.upper()])
        except:
            print('That is not a valid logging level.')
            continue
        else:
            break

    if handler.lower() == 'syslog':
        changed |= maybe_changed(
            which2, 'logging:syslog:facility', get_string,
            '{} syslog facility (e.g., user, daemon, auth):'.format(which))
        changed |= maybe_changed(
            which2, 'logging:syslog:host', get_string_none,
            '{} syslog host (or none for localhost):'.format(which))
        if getter('logging:syslog:host'):
            changed |= maybe_changed(
                which2, 'logging:syslog:port', get_int,
                '{} syslog port:'.format(which))

    return changed


def main(args):
    if args.yes:
        maybe_changed = partial(maybe_changed_extended, use_default=True)
    else:
        maybe_changed = maybe_changed_extended

    generate_key('server', server_user_id)
    generate_key('client', client_user_id)
    import_key('server', client_user_id)
    import_key('client', server_user_id)

    default = not (get_client_setting('loaded') and
                   get_server_setting('loaded'))

    do_config = default if args.yes else \
        get_bool('Do you want to configure things interactively?', default)

    server_changed = client_changed = False

    if do_config:
        server_changed |= maybe_changed(
            'server', 'support_arch_linux', get_bool,
            'Do you want to support Arch Linux clients?')

        if isinstance(get_server_setting('port'), int):
            # Otherwise, the settings file has been edited to make the port
            # either a list of ports or a mapping, and we don't want to try to
            # configure it here.
            server_changed |= maybe_changed(
                'server', 'port', get_int,
                'What port should the server listen on?')

        server_changed |= maybe_changed(
            'server', 'local_port', get_int,
            'What local-only port should the server use?')

        configure_ssl = True
        port = get_server_setting('port')
        if isinstance(port, dict):
            for port_number, port_settings in port.items():
                if 'ssl' in port_settings:
                    # If there are already port-specific SSL settings, then
                    # don't try to configure SSL in this script.
                    configure_ssl = False
        if configure_ssl:
            default = bool(get_server_setting('ssl:certificate', None) or
                           get_server_setting('ssl:key', None))
            configure_ssl = maybe_get_bool(
                'Do you want the server to use SSL?', default, args.yes)
        if not configure_ssl:
            if get_server_setting('ssl:certificate', None):
                set_server_setting('ssl:certificate', None)
                server_changed = True
            if get_server_setting('ssl:key', None):
                set_server_setting('ssl:key', None)
                server_changed = True
        else:
            while True:
                server_changed |= maybe_changed(
                    'server', 'ssl:certificate', get_string,
                    'SSL certificate file path:')
                if os.path.exists(get_server_setting('ssl:certificate')):
                    break
                print('That file does not exist.')

            while True:
                server_changed |= maybe_changed(
                    'server', 'ssl:key', get_string, 'SSL key file path:')
                if os.path.exists(get_server_setting('ssl:key')):
                    break
                print('That file does not exist.')

        server_changed |= maybe_changed('server', 'threaded', get_bool,
                                        'Should the server be multithreaded?')
        server_changed |= maybe_changed('server', 'database:host',
                                        get_string_or_list,
                                        'Database host:port:')
        if get_server_setting('database:host'):
            server_changed |= maybe_changed(
                'server', 'database:replicaset', get_string_none,
                'Replicaset name:', empty_ok=True)
        server_changed |= maybe_changed('server', 'database:name',
                                        get_string, 'Database name:')
        server_changed |= maybe_changed('server', 'database:username',
                                        get_string_none, 'Database username:',
                                        empty_ok=True)
        if get_server_setting('database:username'):
            server_changed |= maybe_changed('server', 'database:password',
                                            get_string, 'Database password:')

        server_changed |= configure_logging('Server', maybe_changed)
        server_changed |= maybe_changed(
            'server', 'audit_cron:enabled', get_bool,
            'Do you want to enable the audit cron job?')

        if get_server_setting('audit_cron:enabled'):
            server_changed |= maybe_changed(
                'server', 'audit_cron:email', get_string,
                'What email address should get the audit output?')

        port = get_server_setting('port')
        if port == 443:
            sample_url = 'https://hostname'
        elif port == 80:
            sample_url = 'http://hostname'
        else:
            sample_url = 'http://hostname:{}'.format(port)
        prompt = 'URL base, e.g., {}, for clients to reach server:'.format(
            sample_url)

        client_changed |= maybe_changed(
            'client', 'server_url', get_string, prompt)

        client_changed |= maybe_changed(
            'client', 'geolocation_api_key', get_string,
            'Google geolocation API key, if any:', empty_ok=True)
        prompter = partial(get_int, minimum=1)
        client_changed |= maybe_changed(
            'client', 'schedule:collect_interval', prompter,
            'How often (minutes) do you want to collect data?')
        client_changed |= maybe_changed(
            'client', 'schedule:submit_interval', prompter,
            'How often (minutes) do you want re-try submits?')

        client_changed |= configure_logging('Client', maybe_changed)

        save_server_settings()
        if server_changed:
            print('Saved server settings.')

        save_client_settings()
        if client_changed:
            print('Saved client settings.')

    service_file = '/etc/systemd/system/penguindome-server.service'
    service_exists = os.path.exists(service_file)
    default = not service_exists

    if service_exists:
        prompt = ("Do you want to replace the server's systemd "
                  "configuration?")
    else:
        prompt = 'Do you want to add the server to systemd?'

    do_service = maybe_get_bool(prompt, default, args.yes)

    if do_service:
        with NamedTemporaryFile('w+') as temp_service_file:
            temp_service_file.write(dedent('''\
                [Unit]
                Description=PenguinDome Server
                After=network.target

                [Service]
                Type=simple
                ExecStart={server_exe}

                [Install]
                WantedBy=multi-user.target
            '''.format(server_exe=os.path.join(top_dir, 'bin', 'server'))))
            temp_service_file.flush()
            os.chmod(temp_service_file.name, 0o644)
            shutil.copy(temp_service_file.name, service_file)
        subprocess.check_output(('systemctl', 'daemon-reload'),
                                stderr=subprocess.STDOUT)
        service_exists = True

    if service_exists:
        try:
            subprocess.check_output(
                ('systemctl', 'is-enabled', 'penguindome-server'),
                stderr=subprocess.STDOUT)
        except:
            if maybe_get_bool('Do you want to enable the server?', True,
                              args.yes):
                subprocess.check_output(
                    ('systemctl', 'enable', 'penguindome-server'),
                    stderr=subprocess.STDOUT)
                is_enabled = True
        else:
            is_enabled = True

        if is_enabled:
            try:
                subprocess.check_output(
                    ('systemctl', 'status', 'penguindome-server'),
                    stderr=subprocess.STDOUT)
            except:
                if maybe_get_bool('Do you want to start the server?', True,
                                  args.yes):
                    subprocess.check_output(
                        ('systemctl', 'start', 'penguindome-server'),
                        stderr=subprocess.STDOUT)
            else:
                if maybe_get_bool('Do you want to restart the server?',
                                  server_changed, args.yes):
                    subprocess.check_output(
                        ('systemctl', 'restart', 'penguindome-server'),
                        stderr=subprocess.STDOUT)

        if get_server_setting('audit_cron:enabled'):
            cron_file = '/etc/cron.d/penguindome-audit'
            cron_exists = os.path.exists(cron_file)

            if cron_exists:
                prompt = 'Do you want to replace the audit crontab?'
            else:
                prompt = 'Do you want to install the audit crontab?'

            do_crontab = maybe_get_bool(
                prompt, args.audit_crontab or not cron_exists,
                args.audit_crontab or args.yes)

            if do_crontab:
                email = get_server_setting('audit_cron:email')
                minute = int(random.random() * 60)
                minute2 = (minute + 1) % 60

                crontab = dedent('''\
                    MAILTO={email}
                    {minute2} * * * * root "{top_dir}/bin/issues" audit
                '''.format(minute2=minute2, email=email, top_dir=top_dir))

                if get_server_setting('support_arch_linux'):
                    template = (
                        '# Run hourly at a random time, so as not to overload '
                        'the Arch server.\n'

                        '{minute} * * * * root "{top_dir}/server/venv" '
                        'python "{top_dir}/server/plugin_managers/'
                        'arch_os_updates.py" --download\n')

                    crontab += template.format(top_dir=top_dir, minute=minute)

                with NamedTemporaryFile('w+') as temp_cron_file:
                    temp_cron_file.write(crontab)
                    temp_cron_file.flush()
                    os.chmod(temp_cron_file.name, 0o644)
                    shutil.copy(temp_cron_file.name, cron_file)

                print('Installed {}'.format(cron_file))

    if client_changed or not glob.glob(os.path.join(releases_dir,
                                                    '*.tar.asc')):
        if client_changed:
            prompt = ('Do you want to build a release with the new client '
                      'settings?')
        else:
            prompt = 'Do you want to build a client release?'

        if maybe_get_bool(prompt, True, args.yes):
            # Sometimes sign fails the first time because of GnuPG weirdness.
            # The client_release script will call sign as well, but we call it
            # first just in case it fails the first time.
            try:
                subprocess.check_output((os.path.join('bin', 'sign'),),
                                        stderr=subprocess.STDOUT)
            except:
                pass
            subprocess.check_output((os.path.join('bin', 'client_release'),),
                                    stderr=subprocess.STDOUT)

    print('Done!')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--yes', '-y', '--noconfirm', action='store_true',
                        help='Use default answers to all questions')
    parser.add_argument('--audit-crontab', action='store_true',
                        help='Replace the audit crontab')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()
    main(args)
