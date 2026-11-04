from __future__ import annotations

import configparser
import json
import os
import subprocess
import sys
from unittest.mock import mock_open
from unittest.mock import patch

import pytest

from pre_commit_hooks import run_in_docker
from pre_commit_hooks.check_yaml import yaml
from pre_commit_hooks.util import cmd_output
from testing.util import git_commit

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTAINER_ID = '0123456789abcdef' * 4
USER_ARGS = ('-u', '1000:1001')
INSPECT_OUTPUT = json.dumps([{
    'Mounts': [
        {
            'Source': '/var/run/docker.sock',
            'Destination': '/var/run/docker.sock',
        },
        {'Source': '/host/work', 'Destination': '/work'},
    ],
}]).encode()

skip_win32 = pytest.mark.skipif(
    sys.platform == 'win32',
    reason='docker hooks only support Linux',
)


def completed(returncode, stdout=b''):
    return subprocess.CompletedProcess(
        args=(),
        returncode=returncode,
        stdout=stdout,
    )


def mountinfo_line(root):
    return f'2 1 8:1 {root} /etc/hostname rw - ext4 /dev/sda1 rw\n'.encode()


@pytest.fixture  # pragma: win32 no cover
def mock_run():
    with patch.object(subprocess, 'run') as mock:
        yield mock


@pytest.fixture  # pragma: win32 no cover
def worktree_dir(temp_git_dir, tmpdir):
    worktree = tmpdir.join('worktree')
    with temp_git_dir.as_cwd():
        git_commit('--allow-empty', '-m', 'init')
        cmd_output('git', 'worktree', 'add', '--detach', str(worktree))
    return worktree


# Container ID

@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    ('mountinfo', 'expected'),
    (
        pytest.param(
            mountinfo_line(f'/var/lib/docker/containers/{CONTAINER_ID}'
                           f'/hostname'),
            CONTAINER_ID,
            id='docker',
        ),
        pytest.param(
            mountinfo_line(f'/containers/overlay-containers/{CONTAINER_ID}'
                           f'/userdata/hostname'),
            CONTAINER_ID,
            id='podman',
        ),
        pytest.param(
            b'1 0 0:1 / / rw - overlay overlay rw\n',
            None,
            id='not-in-container',
        ),
    ),
)
def test_get_container_id(mountinfo, expected):
    with patch('builtins.open', mock_open(read_data=mountinfo)):
        assert run_in_docker._get_container_id() == expected


@skip_win32  # pragma: win32 no cover
@patch('builtins.open', side_effect=FileNotFoundError)
def test_get_container_id_no_mountinfo(mock_file):
    assert run_in_docker._get_container_id() is None


# Docker path

@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    ('container_id', 'inspect', 'path', 'expected'),
    (
        pytest.param(
            None, None, '/work/repo', '/work/repo',
            id='not-in-container',
        ),
        pytest.param(
            CONTAINER_ID, completed(1), '/work/repo', '/work/repo',
            id='container-not-visible',
        ),
        pytest.param(
            CONTAINER_ID,
            completed(0, INSPECT_OUTPUT),
            '/work/repo',
            '/host/work/repo',
            id='mounted',
        ),
        pytest.param(
            CONTAINER_ID,
            completed(0, INSPECT_OUTPUT),
            '/other/repo',
            '/other/repo',
            id='not-mounted',
        ),
    ),
)
@patch.object(run_in_docker, '_get_container_id')
def test_get_docker_path(
        mock_get_container_id, mock_run, container_id, inspect, path,
        expected,
):
    mock_get_container_id.return_value = container_id
    mock_run.return_value = inspect

    assert run_in_docker._get_docker_path(path) == expected


# TTY

@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    ('isatty', 'expected'),
    (
        pytest.param(True, ('--tty',), id='color'),
        pytest.param(False, (), id='no-color'),
    ),
)
@patch.object(sys, 'stdout')
def test_get_docker_tty(mock_stdout, isatty, expected):
    mock_stdout.isatty.return_value = isatty

    assert run_in_docker.get_docker_tty() == expected


# User

@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    ('info', 'expected'),
    (
        pytest.param(
            completed(0, b'{"SecurityOptions":["name=seccomp"]}'),
            False,
            id='rootful',
        ),
        pytest.param(
            completed(
                0,
                b'{"SecurityOptions":["name=seccomp","name=rootless"]}',
            ),
            True,
            id='rootless-docker',
        ),
        pytest.param(
            completed(0, b'{"host":{"security":{"rootless":true}}}'),
            True,
            id='rootless-podman',
        ),
        pytest.param(completed(1), False, id='docker-info-fails'),
    ),
)
def test_is_rootless(mock_run, info, expected):
    mock_run.return_value = info

    assert run_in_docker._is_rootless() == expected


@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    ('rootless', 'expected'),
    (
        pytest.param(False, USER_ARGS, id='rootful'),
        pytest.param(True, (), id='rootless'),
    ),
)
@patch.object(os, 'getgid', return_value=1001)
@patch.object(os, 'getuid', return_value=1000)
@patch.object(run_in_docker, '_is_rootless')
def test_get_docker_user(
        mock_is_rootless, mock_getuid, mock_getgid, rootless, expected,
):
    mock_is_rootless.return_value = rootless

    assert run_in_docker.get_docker_user() == expected


# Main

def fake_docker_path(path):  # pragma: win32 no cover
    return f'/host{path}'


@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    'repo_fixture',
    (
        pytest.param('temp_git_dir', id='clone'),
        pytest.param('worktree_dir', id='worktree'),
    ),
)
@patch.object(
    sys, 'argv', ['run_in_docker.py', 'some-image', 'some-hook', 'file.txt'],
)
@patch.object(run_in_docker, '_get_docker_path', side_effect=fake_docker_path)
@patch.object(run_in_docker, 'get_docker_user', return_value=USER_ARGS)
@patch.object(run_in_docker, 'get_docker_tty', return_value=('--tty',))
def test_main(
        mock_get_docker_tty, mock_get_docker_user, mock_get_docker_path,
        request, repo_fixture, temp_git_dir,
):
    repo = request.getfixturevalue(repo_fixture)
    repo_dir = os.path.realpath(repo)
    git_dir = os.path.realpath(temp_git_dir.join('.git'))

    # The fixture runs git with subprocess.call, so patch it only here
    with repo.as_cwd():
        with patch.object(subprocess, 'call', return_value=0) as mock_call:
            ret = run_in_docker.main()

    assert ret == 0
    mock_call.assert_called_once_with((
        'docker', 'run', '--rm', '--tty', *USER_ARGS,
        '-v', f'/host{repo_dir}:{repo_dir}:rw,Z',
        '-v', f'/host{git_dir}:{git_dir}:rw,Z',
        '--workdir', repo_dir,
        'some-image', 'some-hook', 'file.txt',
    ))


# Hook config

def load_hooks():
    with open(os.path.join(REPO_DIR, '.pre-commit-hooks.yaml')) as f:
        return yaml.load(f)


def test_docker_hooks_use_run_in_docker():
    for hook in load_hooks():
        if hook['language'] != 'fail':
            assert hook['language'] == 'python'
            assert hook['entry'].startswith('run-in-docker ')


def test_hooks_use_image_matching_version():
    config = configparser.ConfigParser()
    config.read(os.path.join(REPO_DIR, 'setup.cfg'))
    version = config['metadata']['version']
    index = version.rindex('.')
    tag = f'{version[:index]}-{version[index + 1:]}'
    image = f'artifactory.adtran.com/docker/pre-commit-hooks:{tag}'

    for hook in load_hooks():
        if 'pre-commit-hooks:' in hook['entry']:
            assert hook['entry'].split()[1] == image
