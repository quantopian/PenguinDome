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
import pwd
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
    gpg_user_id as client_user_id,
)
from penguindome.server import (
    get_setting as get_server_setting,
    set_setting as set_server_setting,
    save_settings as save_server_settings,
    gpg_user_id as server_user_id,
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
    except Exception:
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
    except Exception:
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
        except Exception:
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

    # We will be running penguindome under a locked down account, to do so we need to create a system account,
    #  tell the service files to run penguin dome under that account, change the owner of the penguindome files
    #  to be owned by penguindome, but callable by the user, and make sure the web socket can be talked to by penguindome.
    #  before we do any of that though, we need to create the acount, and keep track of the user running the script as they will
    #  most likely be the one administering penguindome. since this installer needs to be ran as root, handle the condition where they use sudo!
    currentUserName = os.getenv("SUDO_USER") if os.getenv("SUDO_USER") else os.getenv("USER")
    penguinDomeUserName = "PenguinDomeSVC"
    
    if not penguinDomeUserName in [x.pw_name for x in pwd.getpwall()]:
        try:
            subprocess.check_output(('useradd', '-r', '-s', '/bin/nologin', penguinDomeUserName), stderr=subprocess.STDOUT)
        except Exception:
            print("Could not create penguindome user!")

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

        server_changed |= maybe_changed('server', 'database:host', get_string_or_list, 'Database host:port:')
        if get_server_setting('database:host'):
            server_changed |= maybe_changed('server', 'database:replicaset', get_string_none,'Replicaset name:', empty_ok=True)
        server_changed |= maybe_changed('server', 'database:name',get_string, 'Database name:')
        server_changed |= maybe_changed('server', 'database:username',get_string_none, 'Database username:',empty_ok=True)
        server_changed |= maybe_changed('server', 'database:ssl_ca',get_string_none, 'Database SSL CA file (empty for none):',empty_ok=True)

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

    nginx_site_file = '/etc/nginx/sites-enabled/penguindome'
    service_exists = os.path.exists(nginx_site_file)
    default = not service_exists

    do_redis = maybe_get_bool("do you want to configure redis?", default, args.yes)
    if do_redis:
        try:
            subprocess.check_output( ('sed', '-i', 's/supervised no/supervised systemd/', '/etc/redis/redis.conf'), stderr=subprocess.STDOUT)
        except Exception as e:
            pass

        try:
            subprocess.check_output(('systemctl', 'daemon-reload'), stderr=subprocess.STDOUT)
        except Exception:
            pass


        try:
            subprocess.check_output(('systemctl', 'is-enabled', 'redis'), stderr=subprocess.STDOUT)
        except Exception:
            try:
                subprocess.check_output(('systemctl', 'enable', 'redis'), stderr=subprocess.STDOUT)
                is_enabled = True
            except Exception:
                print("Error when enabling redis with systemd!")
        else:
            is_enabled = True

        if is_enabled:
            try:
                subprocess.check_output(('systemctl', 'status', 'redis'), stderr=subprocess.STDOUT)
            except Exception:
                if maybe_get_bool('Do you want to start redis?', True, args.yes):
                    subprocess.check_output(('systemctl', 'start', 'redis'), stderr=subprocess.STDOUT)
            else:
                if maybe_get_bool('Do you want to restart redis?', server_changed, args.yes):
                    subprocess.check_output(('systemctl', 'restart', 'redis'), stderr=subprocess.STDOUT)
        
    if service_exists:
        prompt = ("Do you want to replace the server's webserver "
                  "configuration?")
    else:
        prompt = 'Do you want to add the server to autostart?'

    do_service = maybe_get_bool(prompt, default, args.yes)

    if do_service:
        ### do_service needs to complete the following:
        ###   1) ask to disable the default site, as penguindome might be on port 80
        ###   2) create the nginx site using the given port / ssl values
        ###   3) create a service to make sure the socket file exists in tmp that the nginx service uses
        ###   4) create a service to run our wsgi server (gunicorn)

        #1 - disable default site, nginx is reloaded below, so dont worry about reloading it here!
        rm_default_nginx_site = maybe_get_bool(
                'Do you want to remove the default NGINX site? you should do this if you are using penguindome on port 80', default, args.yes)
        if rm_default_nginx_site:
            try:
                subprocess.check_output(('rm', '/etc/nginx/sites-enabled/default'), stderr=subprocess.STDOUT)
            except Exception:
                print("ERROR when removing nginx default site (at /etc/nginx/sites-enabled/default). manually remove after the installation is complete and reload nginx!")

        
        #2 - create our nginx reverse proxy to our app
        if get_server_setting('ssl:enabled'):
            ssl_port = get_server_setting('port')
            nginx_listen_string = str(ssl_port)+" ssl;"
            nginx_ssl_params = '''
                                \tssl_certificate = {crt};
                                \tssl_certificate_key = {key};
            '''.format(crt = get_server_setting('ssl:certificate'), key = get_server_setting('ssl:key'))
        else:
            plaintext_port = get_server_setting('port')
            nginx_listen_string = str(plaintext_port)+';'
            nginx_ssl_params = ""

        with NamedTemporaryFile('w+') as temp_nginx_site_file:
            temp_nginx_site_file.write(dedent('''\
                server {{
                \tlisten {listen_str}
                {ssl_params}
                \tclient_max_body_size 2G;
                \tkeepalive_timeout 60;

                \tlocation / {{
                    \t\tinclude uwsgi_params;
                    \t\tproxy_pass http://unix:/tmp/penguindome.sock;
                \t}}
                }}
                
                server {{
                \tlisten 127.0.0.1:{local_port};
                {ssl_params}
                \tclient_max_body_size 2G;
                \tkeepalive_timeout 60;

                \tlocation / {{
                    \t\tinclude uwsgi_params;
                    \t\tproxy_pass http://unix:/tmp/penguindome.sock;
                \t}}
                }}
            '''.format(listen_str=nginx_listen_string, ssl_params=nginx_ssl_params, local_port=get_server_setting('local_port'))))
            temp_nginx_site_file.flush()
            os.chmod(temp_nginx_site_file.name, 0o644)
            shutil.copy(temp_nginx_site_file.name, nginx_site_file)
        
        #2 - create a systemd service to make sure our gunicorn socket file always exists before gunicorn starts
        with NamedTemporaryFile('w+') as temp_gunicorn_sock_service_file:
            temp_gunicorn_sock_service_file.write(dedent('''\
                    [Unit]
                    Description=gunicorn socket for penguindome server

                    [Socket]
                    ListenStream=/tmp/penguindome.sock
                    SocketUser={Username}
                    SocketGroup=www-data
                    SocketMode=660

                    [Install]
                    WantedBy=sockets.target
            '''.format(Username=penguinDomeUserName)))
            temp_gunicorn_sock_service_file.flush()
            os.chmod(temp_gunicorn_sock_service_file.name, 0o644)
            os.chown(temp_gunicorn_sock_service_file.name, 0, 0) 
            shutil.copy(temp_gunicorn_sock_service_file.name, "/etc/systemd/system/penguindome_gunicorn.socket")

        #3 - create a systemd service to run gunicorn
        with NamedTemporaryFile('w+') as temp_gunicorn_server_service_file:
            temp_gunicorn_server_service_file.write(dedent('''\
                [Unit]
                Description=penguindome gunicorn daemon
                Requires=penguindome_gunicorn.socket
                After=network.target

                [Service]
                Type=notify
                # the specific user that our service will run as
                User={Username}
                Group={Username}
                RuntimeDirectory=gunicorn
                WorkingDirectory={server_app_folder}
                Environment="PATH={server_venv}/bin"
                ExecStart={server_venv}/bin/gunicorn --workers 1 --bind unix:/tmp/penguindome.sock server:app
                ExecReload=/bin/kill -s HUP $MAINPID
                KillMode=mixed
                TimeoutStopSec=5
                PrivateTmp=true

                [Install]
                WantedBy=multi-user.target
            ''').format(
                    server_venv = top_dir+"/var/server-venv",
                    server_app_folder = top_dir+"/server",
                    Username = penguinDomeUserName
                    ))
            temp_gunicorn_server_service_file.flush()
            os.chmod(temp_gunicorn_server_service_file.name, 0o644)
            os.chown(temp_gunicorn_server_service_file.name, 0, 0) 
            shutil.copy(temp_gunicorn_server_service_file.name, "/etc/systemd/system/penguindome_gunicorn.service")

        

        service_exists = True

    if service_exists:
        #do a reload since we made new service files!
        try:
            subprocess.check_output(('systemctl', 'daemon-reload'), stderr=subprocess.STDOUT)
        except Exception:
            pass


        try:
            subprocess.check_output(('systemctl', 'is-enabled', 'penguindome_gunicorn'), stderr=subprocess.STDOUT)
        except Exception:
            if maybe_get_bool('Do you want to enable the PenguinDome server?', True, args.yes):
                subprocess.check_output(('systemctl', 'enable', 'penguindome_gunicorn'), stderr=subprocess.STDOUT)
                is_enabled = True
        else:
            is_enabled = True

        if is_enabled:
            try:
                subprocess.check_output(('systemctl', 'status', 'penguindome_gunicorn'), stderr=subprocess.STDOUT)
            except Exception:
                if maybe_get_bool('Do you want to start the PenguinDome server?', True, args.yes):
                    subprocess.check_output(('systemctl', 'start', 'penguindome_gunicorn'), stderr=subprocess.STDOUT)
            else:
                if maybe_get_bool('Do you want to restart the PenguinDome server?', server_changed, args.yes):
                    subprocess.check_output(('systemctl', 'restart', 'penguindome_gunicorn'), stderr=subprocess.STDOUT)

            if maybe_get_bool('Do you want to reload nginx?', server_changed, args.yes):
                subprocess.check_output(('systemctl', 'reload', 'nginx'), stderr=subprocess.STDOUT)

        
        
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
                    {minute2} * * * * root "{top_dir}/bin/issues" audit --cron
                '''.format(minute2=minute2, email=email, top_dir=top_dir))

                with NamedTemporaryFile('w+') as temp_cron_file:
                    temp_cron_file.write(crontab)
                    temp_cron_file.flush()
                    os.chmod(temp_cron_file.name, 0o644)
                    shutil.copy(temp_cron_file.name, cron_file)

                print('Installed {}'.format(cron_file))

        #Check the file permissions
        fixFilePermissionsDefault = False
        if not((pwd.getpwuid(os.stat(__file__).st_uid).pw_name == penguinDomeUserName) and (pwd.getpwuid(os.stat(__file__).st_gid).pw_name == currentUserName)):
            fixFilePermissionsDefault = True
        
        fixFiles = maybe_get_bool('Do you want to change fix the file ownership on your PenguinDome install?', fixFilePermissionsDefault, args.yes)
        if fixFiles:
            try:
                subprocess.check_output(('chown', '-R', penguinDomeUserName+":"+currentUserName, top_dir), stderr=subprocess.STDOUT)
            except Exception:
                print("Error setting ownership of files!")

            

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
            except Exception:
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
