#!/usr/bin/env python3

from base64 import b64decode
import filecmp
import os
import re
import shutil
import socket
import subprocess
import sys
from tempfile import mkdtemp

from qlmdm import (
    top_dir,
    set_gpg,
    release_file,
    server_request,
    var_dir,
    signatures_dir,
    gpg_command,
)
from qlmdm.client import get_logger

log = get_logger('update')

os.chdir(top_dir)
set_gpg('client')


def do_release(data):
    log.info('Updating to {}', data['current_release'])
    unpack_dir = mkdtemp(dir=var_dir)
    try:
        update_tar = os.path.join(unpack_dir, 'release.tar')
        update_signed = update_tar + '.asc'
        open(update_signed, 'w').write(data['update'])
        gpg_command('--verify', update_signed)
        gpg_command(update_signed)
        subprocess.check_output(('tar', '--file', update_tar,
                                 '--directory', unpack_dir,
                                 '--extract'))
        os.unlink(update_signed)
        os.unlink(update_tar)

        # Identify obsolete files that will be removed.
        old_signatures = set(recursive_list(signatures_dir))
        new_signatures = set(recursive_list(
            os.path.join(unpack_dir, signatures_dir)))
        obsolete_files = old_signatures - new_signatures
        suffix_re = re.compile(r'\.sig$')
        obsolete_files = \
            [os.path.join('signatures', f) for f in obsolete_files] + \
            [suffix_re.sub('', f) for f in obsolete_files]

        # Move updated files into place.
        for file in recursive_list(unpack_dir):
            src = os.path.join(unpack_dir, file)
            target = os.path.join(top_dir, file)
            if not os.path.exists(os.path.dirname(target)):
                os.makedirs(os.path.dirname(target))
            try:
                if filecmp.cmp(src, target, shallow=False):
                    log.debug('Identical (not replaced): {}', file)
                    continue
                else:
                    log.info('Replacing {}', file)
            except:
                log.info('New file {}', file)
            shutil.move(src, target)

        for file in obsolete_files:
            log.info('Deleting obsolete {}', file)
            try:
                os.remove(file)
            except FileNotFoundError:
                log.warn('Failed to delete {} (already gone)', file)
                pass
    finally:
        shutil.rmtree(unpack_dir)


def do_patches(patches):
    for patch in patches:
        patch_id = patch['id']
        for patch_file in patch['files']:
            patch_path = patch_file['path']
            patch_mode = patch_file['mode']
            patch_content = b64decode(patch_file.get('content', ''))

            if patch_path.startswith('/'):
                log.error('Ignoring absolute patch {}', patch_path)
                continue
            if '..' in os.sep.split(patch_path):
                log.error('Ignoring patch {} with ".." in it', patch_path)
                continue
            if patch_mode == 0:
                if patch_content:
                    log.error(
                        "Patch for {}, mode 0, has content but shouldn't",
                        patch_path)
                    continue
                if os.path.exists(patch_path):
                    log.info('Removing {} due to patch', patch_path)
                    try:
                        os.remove(patch_path)
                    except FileNotFoundError:
                        log.warn('Failed to delete {} (already gone)',
                                 patch_path)
                        pass
                else:
                    log.warn("Patch says to remove {} but it's already gone",
                             patch_path)
                continue
            log.info('Patching {} (id {}, mode {})', patch_path, patch_id,
                     patch_mode)
            patch_dir = os.path.dirname(os.path.join(top_dir, patch_path))
            if not os.path.exists(patch_dir):
                os.makedirs(patch_dir)
            open(patch_path, 'wb').write(patch_content)
            os.chmod(patch_path, patch_mode)

        server_request('/qlmdm/v1/acknowledge_patch',
                       data={'id': patch_id,
                             'hostname': socket.gethostname()})


def main():
    try:
        current_release = int(open(release_file).read().strip())
    except:
        current_release = 0

    data = {'old_release': current_release,
            'hostname': socket.gethostname()}

    log.debug('Sending: {}', data)

    response = server_request('/qlmdm/v1/update', data=data)
    data = response.json()

    changed = False

    if data['status'] == 'current':
        log.debug('Current')
        pass
    elif data['status'] == 'out-of-date':
        do_release(data)
        changed = True
    else:
        log.exception('Unrecognized status: {}'.format(data['status']))
        sys.exit(1)

    if 'patches' in data:
        do_patches(data['patches'])
        changed = True

    if changed:
        subprocess.check_output(os.path.join('bin', 'verify'))
        log.info('Successful update')


def recursive_list(top_dir):
    for dirpath, dirnames, filenames in os.walk(top_dir):
        dirpath = dirpath[len(top_dir)+1:]
        for filename in filenames:
            yield os.path.join(dirpath, filename)


if __name__ == '__main__':
    main()
