import re

import pytest

from penguindome.server import get_db
from server import client_parameters


def test_parse_args_no_arguments(capsys):
    with pytest.raises(SystemExit) as e:
        client_parameters.parse_args(())
    assert e.type == SystemExit
    assert e.value.code == 2
    captured = capsys.readouterr()
    assert 'the following arguments are required: command' in captured.err


def test_parse_args_sys_argv(mocker):
    mocker.patch('sys.argv', ('ls',))
    args = client_parameters.parse_args()
    assert args.func == client_parameters.ls_handler


def test_parse_args_ls(capsys):
    args = client_parameters.parse_args(('ls',))
    assert args.func == client_parameters.ls_handler
    assert args.hostname is None
    assert args.parameter is None

    args = client_parameters.parse_args(('ls', '--hostname', 'froodle'))
    assert args.func == client_parameters.ls_handler
    assert args.hostname == ['froodle']
    assert args.parameter is None

    with pytest.raises(SystemExit) as e:
        args = client_parameters.parse_args(('ls', '--parameter', 'freedle'))
    assert e.type == SystemExit
    assert e.value.code == 2
    captured = capsys.readouterr()
    assert 'invalid choice' in captured.err

    args = client_parameters.parse_args(('ls', '--parameter', 'user_email'))
    assert args.func == client_parameters.ls_handler
    assert args.hostname is None
    assert args.parameter == ['user_email']


def test_parse_args_set(capsys):
    with pytest.raises(SystemExit) as e:
        args = client_parameters.parse_args(('set',))
    assert e.type == SystemExit
    assert e.value.code == 2
    captured = capsys.readouterr()
    assert 'arguments are required: --hostname, --parameter, VALUE' in \
        captured.err

    with pytest.raises(SystemExit) as e:
        args = client_parameters.parse_args(('set', '--hostname', 'froodle',
                                             '--parameter', 'freedle',
                                             'frondle'))
    assert e.type == SystemExit
    assert e.value.code == 2
    captured = capsys.readouterr()
    assert 'invalid choice' in captured.err

    args = client_parameters.parse_args(('set', '--hostname', 'froodle',
                                         '--parameter', 'user_email',
                                         'frondle'))
    assert args.hostname == 'froodle'
    assert args.parameter == 'user_email'
    assert args.value == ['frondle']


def test_parse_args_unset(capsys):
    with pytest.raises(SystemExit) as e:
        args = client_parameters.parse_args(('unset',))
    assert e.type == SystemExit
    assert e.value.code == 2
    captured = capsys.readouterr()
    assert 'arguments are required: --hostname, --parameter' in captured.err

    with pytest.raises(SystemExit) as e:
        args = client_parameters.parse_args(('unset', '--hostname', 'froodle',
                                             '--parameter', 'freedle'))
    assert e.type == SystemExit
    assert e.value.code == 2
    captured = capsys.readouterr()
    assert 'invalid choice' in captured.err

    args = client_parameters.parse_args(('unset', '--hostname', 'froodle',
                                         '--parameter', 'user_email'))
    assert args.hostname == 'froodle'
    assert args.parameter == 'user_email'


def test_handlers(capsys, mongodb):
    get_db(mongodb)
    mongodb.clients.insert_many([{'hostname': 'froodle'},
                                 {'hostname': 'frondle'}])

    args = client_parameters.parse_args(('ls',))
    args.func(args)
    captured = capsys.readouterr()
    assert captured.out == ""

    args = client_parameters.parse_args(('set', '--hostname', 'froodle',
                                         '--parameter', 'user_email',
                                         'example@example.com'))
    args.func(args)

    args = client_parameters.parse_args(('ls',))
    args.func(args)
    captured = capsys.readouterr()
    assert re.search(r'^froodle\s+user_email\s+example@example\.com\s*$',
                     captured.out, re.MULTILINE) is not None

    args = client_parameters.parse_args(('set', '--hostname', 'froodle',
                                         '--parameter', 'user_clients',
                                         'frondle'))
    args.func(args)

    args = client_parameters.parse_args(('ls',))
    args.func(args)
    captured = capsys.readouterr()
    assert re.search(r'^froodle\s+user_clients\s+\[\'frondle\'\]\s*$',
                     captured.out, re.MULTILINE) is not None
    assert re.search(r'^frondle\s+user_clients\s+\[\'froodle\'\]\s*$',
                     captured.out, re.MULTILINE) is not None

    args = client_parameters.parse_args(('ls', '--parameter', 'user_email'))
    args.func(args)
    captured = capsys.readouterr()
    assert 'user_clients' not in captured.out
    assert re.search(r'^froodle\s+user_email\s+', captured.out, re.MULTILINE) \
        is not None

    args = client_parameters.parse_args(('ls', '--parameter', 'user_clients'))
    args.func(args)
    captured = capsys.readouterr()
    assert 'user_email' not in captured.out
    assert re.search(r'^froodle\s+user_clients\s+', captured.out,
                     re.MULTILINE) is not None

    args = client_parameters.parse_args(('unset', '--hostname', 'froodle',
                                         '--parameter', 'user_email'))
    args.func(args)

    args = client_parameters.parse_args(('ls',))
    args.func(args)
    captured = capsys.readouterr()
    assert re.search(r'^froodle\s+user_email\s+',
                     captured.out, re.MULTILINE) is None

    args = client_parameters.parse_args(('unset', '--hostname', 'froodle',
                                         '--parameter', 'user_clients'))
    args.func(args)

    args = client_parameters.parse_args(('ls',))
    args.func(args)
    captured = capsys.readouterr()
    assert re.search(r'^froodle\s+user_clients\s+',
                     captured.out, re.MULTILINE) is None
