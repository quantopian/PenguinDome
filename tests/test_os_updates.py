import os
import tempfile
import time
from unittest import mock

import pytest

from client.plugins import os_updates


# This test unfortunately does not currently work. See
# https://github.com/aklajnert/pytest-subprocess/issues/16.
@pytest.mark.xfail
def test_ubuntu_checker_no_do_release_upgrade(fake_process):
    def raise_oserror(process):
        raise OSError()

    fake_process.register_subprocess(('do-release-upgrade', '-c'),
                                     callback=raise_oserror)
    ret = os_updates.ubuntu_checker()
    assert ret is None


def test_ubuntu_checker_release_update_available(fake_process):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    # stderr=() is necessary here and below because of
    # https://github.com/aklajnert/pytest-subprocess/issues/17.
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("0;0",))
    ret = os_updates.ubuntu_checker()
    assert ret['release'] is True


def test_ubuntu_checker_no_release_update_available(fake_process):
    fake_process.register_subprocess(('do-release-upgrade', '-c'),
                                     returncode=1)
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("0;0",))
    ret = os_updates.ubuntu_checker()
    assert ret['release'] is False


@pytest.fixture
def os_stat():
    # May be relevant later: currently only mocks the first time each path is
    # stat'd.
    orig_os_stat = os.stat
    file_mappings = {}

    def add_mapping(original, replacement):
        file_mappings[original] = replacement

    def my_os_stat(*args, **kwargs):
        if args[0] in file_mappings:
            args = (file_mappings.pop(args[0]),) + args[1:]
        return orig_os_stat(*args, **kwargs)

    with mock.patch('os.stat', my_os_stat):
        yield add_mapping
        if file_mappings:
            raise NotImplementedError('Orphaned os.stat calls: ' +
                                      ', '.join(file_mappings.keys()))


def test_ubuntu_checker_current(fake_process, os_stat):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("0;0",))
    with tempfile.NamedTemporaryFile() as f:
        os_stat('/var/lib/apt/periodic/update-success-stamp', f.name)
        ret = os_updates.ubuntu_checker()
    assert ret['current'] is True


def test_ubuntu_checker_not_current_not_found(fake_process, os_stat):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("0;0",))
    with tempfile.NamedTemporaryFile(delete=False) as f:
        os_stat('/var/lib/apt/periodic/update-success-stamp', f.name)
        os.unlink(f.name)
        ret = os_updates.ubuntu_checker()
    assert ret['current'] is False


def test_ubuntu_checker_not_current_old(fake_process, os_stat):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("0;0",))
    with tempfile.NamedTemporaryFile() as f:
        os_stat('/var/lib/apt/periodic/update-success-stamp', f.name)
        t = time.time() - 60 * 60 * 24 * 3
        os.utime(f.name, (t, t))
        ret = os_updates.ubuntu_checker()
    assert ret['current'] is False


# This test unfortunately does not currently work. See
# https://github.com/aklajnert/pytest-subprocess/issues/16.
@pytest.mark.xfail
def test_ubuntu_checker_no_apt_check(fake_process):
    def raise_oserror(process):
        raise OSError()

    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("0;0",),
                                     callback=raise_oserror)
    ret = os_updates.ubuntu_checker()
    assert ret['patches'] == 'unknown'


def test_ubuntu_checker_no_patches(fake_process):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("0;0",))
    ret = os_updates.ubuntu_checker()
    assert ret['patches'] is False


def test_ubuntu_checker_patches(fake_process):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("1;0",))
    ret = os_updates.ubuntu_checker()
    assert ret['patches'] is True


def test_ubuntu_checker_no_security(fake_process):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("1;0",))
    ret = os_updates.ubuntu_checker()
    assert ret['security_patches'] is False


def test_ubuntu_checker_security(fake_process):
    fake_process.register_subprocess(('do-release-upgrade', '-c'))
    fake_process.register_subprocess('/usr/lib/update-notifier/apt-check',
                                     stderr=(), stdout=("1;1",))
    ret = os_updates.ubuntu_checker()
    assert ret['security_patches'] is True
