#!/usr/bin/env python

import logbook
import os
import subprocess
import shutil
from tempfile import NamedTemporaryFile
from textwrap import dedent
import yaml

from qlmdm import top_dir, gpg_private_home, gpg_public_home, set_gpg
from qlmdm.prompts import get_bool, get_int, get_string, get_string_or_list

os.chdir(top_dir)

if not os.path.exists(gpg_private_home):
    os.makedirs(gpg_private_home, 0700)
if not os.path.exists(gpg_public_home):
    os.makedirs(gpg_public_home, 0700)

server_user_id = 'qlmdm-server'
client_user_id = 'qlmdm-client'

entropy_warned = False


def entropy_warning():
    global entropy_warned

    if entropy_warned:
        return
    entropy_warned = True

    print dedent('''
        If this takes a long time to run, you may want to install haveged or
        some other tool for adding entropy to the kernel.
    ''')


def generate_key(mode, user_id):
    set_gpg(mode)
    try:
        subprocess.check_output(('gpg', '--list-keys', user_id),
                                stderr=subprocess.STDOUT)
    except:
        entropy_warning()
        subprocess.check_output(('gpg', '--batch', '--passphrase', '',
                                 '--quick-gen-key', user_id),
                                stderr=subprocess.STDOUT)


def import_key(to_mode, user_id):
    from_mode = 'client' if to_mode == 'server' else 'server'
    set_gpg(to_mode)
    try:
        subprocess.check_output(('gpg', '--list-keys', user_id),
                                stderr=subprocess.STDOUT)
    except:
        with NamedTemporaryFile() as key_file, \
             NamedTemporaryFile() as trust_file:
            set_gpg(from_mode)
            subprocess.check_output(('gpg', '--batch', '--yes', '--export',
                                     '-o', key_file.name, user_id),
                                    stderr=subprocess.STDOUT)
            subprocess.check_call(('gpg', '--batch', '--yes',
                                   '--export-ownertrust'),
                                  stdout=trust_file)
            trust_file.seek(0)
            set_gpg(to_mode)
            subprocess.check_output(('gpg', '--batch', '--import',
                                     key_file.name), stderr=subprocess.STDOUT)
            subprocess.check_output(('gpg', '--batch', '--import-ownertrust',
                                     trust_file.name),
                                    stdin=trust_file, stderr=subprocess.STDOUT)


generate_key('server', server_user_id)
generate_key('client', client_user_id)
import_key('server', client_user_id)
import_key('client', server_user_id)


def configure_logging(settings, which):
    settings['logging'] = settings.get('logging', {})

    while True:
        handler = get_string(
            '{} logbook handler (e.g., stderr, syslog):'.format(which),
            settings['logging'].get('handler', 'stderr'))
        full_handler = handler.lower() + 'handler'
        try:
            next(h for h in logbook.__dict__ if h.lower() == full_handler)
        except StopIteration:
            print('That is not a valid handler.')
            continue
        else:
            break
    settings['logging']['handler'] = handler

    while True:
        level = get_string(
            '{} logging level (e.g., debug, info):'.format(which),
            settings['logging'].get('level', 'debug'))
        try:
            int(logbook.__dict__[level.upper()])
        except:
            print('That is not a valid logging level.')
            continue
        else:
            break
    settings['logging']['level'] = level

    if handler.lower() == 'syslog':
        settings['logging']['facility'] = get_string(
            '{} syslog facility (e.g., user, daemon, auth):'.format(which),
            settings['logging'].get('facility', 'user'))


try:
    server_settings = yaml.load(open('server/settings.yml'))
except:
    server_settings = {}

try:
    client_settings = yaml.load(open('client/settings.yml'))
except:
    client_settings = {}

if server_settings and client_settings:
    default = False
else:
    default = True

do_config = get_bool('Do you want to configure things interactively?', default)

if do_config:
    server_settings['port'] = get_int(
        'What port should the server listen on?',
        server_settings.get('port', 80))

    server_settings['threaded'] = get_bool(
        'Should the server be multithreaded?',
        server_settings.get('threaded', True))

    server_settings['database'] = server_settings.get('database', {})

    server_settings['database']['host'] = get_string_or_list(
        'Database host:port:', server_settings['database'].get('host', []))

    replicaset = get_string(
        'Replicaset name:', server_settings['database'].get('replicaset', ''),
        none_ok=True)
    if replicaset:
        server_settings['database']['replicaset'] = replicaset
    else:
        server_settings['database'].pop('replicaset', None)

    server_settings['database']['name'] = get_string(
        'Database name:', server_settings['database'].get('name', 'qlmdm'))

    username = get_string(
        'Database username:', server_settings['database'].get('username', ''),
        none_ok=True)
    if username:
        server_settings['database']['username'] = username
    else:
        server_settings['database'].pop('username', None)

    if username:
        server_settings['database']['password'] = get_string(
            'Database password:',
            server_settings['database'].get('password', None))
    else:
        server_settings['database'].pop('password', None)

    configure_logging(server_settings, 'Server')

    server_settings['audit_cron'] = server_settings.get('audit_cron', {})

    do_audit = get_bool('Do you want to enable the audit cron job?',
                        server_settings['audit_cron'].get('enabled', True))
    server_settings['audit_cron']['enabled'] = do_audit

    if do_audit:
        audit_email = get_string(
            'What email address should get the audit output?',
            server_settings['audit_cron'].get('email', None))
        server_settings['audit_cron']['email'] = audit_email

    if server_settings['port'] == 443:
        sample_url = 'https://hostname'
    elif server_settings['port'] == 80:
        sample_url = 'http://hostname'
    else:
        sample_url = 'http://hostname:{}'.format(server_settings['port'])

    client_settings['server_url'] = get_string(
        'URL base, e.g., {}, for clients to research server:'.format(
            sample_url),
        client_settings.get('server_url', None))

    api_key = get_string(
        'Google geolocation API key, if any:',
        client_settings.get('geolocation_api_key', ''))
    if api_key:
        client_settings['geolocation_api_key'] = api_key
    else:
        client_settings.pop('geolocation_api_key', None)

    client_settings['schedule'] = client_settings.get('schedule', {})

    client_settings['schedule']['collect_interval'] = get_int(
        'How often (minutes) do you want to collect data?',
        client_settings['schedule'].get('collect_interval', 5),
        minimum=1)

    client_settings['schedule']['submit_interval'] = get_int(
        'How often (minutes) do you want re-try submits?',
        client_settings['schedule'].get('submit_interval', 1),
        minimum=1)

    configure_logging(client_settings, 'Client')

    yaml.dump(server_settings, open('server/settings.yml', 'w'))
    print('Saved server/settings.yml')

    yaml.dump(client_settings, open('client/settings.yml', 'w'))
    print('Saved client/settings.yml')

service_file = '/etc/systemd/system/qlmdm-server.service'
service_exists = os.path.exists(service_file)
default = not service_exists

if service_exists:
    prompt = "Do you want to replace the server's systemd configuration?"
else:
    prompt = 'Do you want to add the server to systemd?'

do_service = get_bool(prompt, default)

if do_service:
    with NamedTemporaryFile() as temp_service_file:
        temp_service_file.write(dedent('''\
            [Unit]
            Description=Quantopian Linux MDM Server
            After=network.target

            [Service]
            Type=simple
            ExecStart={server_exe}

            [Install]
            WantedBy=multi-user.target
        '''.format(server_exe=os.path.join(top_dir, 'bin', 'server'))))
        temp_service_file.flush()
        os.chmod(temp_service_file.name, 0644)
        shutil.copy(temp_service_file.name, service_file)
    subprocess.check_output(('systemctl', 'daemon-reload'),
                            stderr=subprocess.STDOUT)
    service_exists = True

if server_settings and service_exists:
    try:
        subprocess.check_output(('systemctl', 'is-enabled', 'qlmdm-server'),
                                stderr=subprocess.STDOUT)
    except:
        if get_bool('Do you want to enable the server?', True):
            subprocess.check_output(('systemctl', 'enable', 'qlmdm-server'),
                                    stderr=subprocess.STDOUT)
            is_enabled = True
    else:
        is_enabled = True

if is_enabled:
    try:
        subprocess.check_output(('systemctl', 'status', 'qlmdm-server'),
                                stderr=subprocess.STDOUT)
    except:
        if get_bool('Do you want to start the server?', True):
            subprocess.check_output(('systemctl', 'start', 'qlmdm-server'),
                                    stderr=subprocess.STDOUT)

try:
    cron_enabled = server_settings['audit_cron']['enabled']
except:
    cron_enabled = False

if cron_enabled:
    cron_file = '/etc/cron.d/qlmdm-audit'
    cron_exists = os.path.exists(cron_file)

    if cron_exists:
        prompt = 'Do you want to replace the audit crontab?'
    elif not do_config:
        prompt = 'Do you want to install the audit crontab?'
    else:
        prompt = None

    if prompt:
        do_crontab = get_bool(prompt, not cron_exists)
    else:
        do_crontab = True

    if do_crontab:
        email = server_settings['audit_cron']['email']

        with NamedTemporaryFile() as temp_cron_file:
            temp_cron_file.write(dedent('''\
                MAILTO={email}
                * * * * * root {top_dir}/bin/audit
            '''.format(email=email, top_dir=top_dir)))
            temp_cron_file.flush()
            os.chmod(temp_cron_file.name, 0644)
            shutil.copy(temp_cron_file.name, cron_file)

        print('Installed {}'.format(cron_file))
