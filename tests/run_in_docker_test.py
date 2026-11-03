from __future__ import annotations

import configparser
import os
import subprocess
import sys

import pytest

from pre_commit_hooks.check_yaml import yaml
from pre_commit_hooks.util import cmd_output
from testing.util import git_commit

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_DIR, 'run-in-docker.sh')
ROOTFUL_INFO = '{"SecurityOptions":["name=seccomp"]}'
FAKE_DOCKER = '''\
#!/bin/sh
if [ "$1" = info ]; then
    echo "$FAKE_DOCKER_INFO"
else
    printf '%s\\n' "$@"
fi
'''

skip_win32 = pytest.mark.skipif(
    sys.platform == 'win32',
    reason='run-in-docker.sh is a bash script',
)


@pytest.fixture  # pragma: win32 no cover
def fake_docker_path(tmpdir):
    bin_dir = tmpdir.join('bin')
    docker = bin_dir.ensure('docker')
    docker.write(FAKE_DOCKER)
    docker.chmod(0o755)
    return f'{bin_dir}{os.pathsep}{os.environ["PATH"]}'


@pytest.fixture  # pragma: win32 no cover
def worktree_dir(temp_git_dir, tmpdir):
    worktree = tmpdir.join('worktree')
    with temp_git_dir.as_cwd():
        git_commit('--allow-empty', '-m', 'init')
        cmd_output('git', 'worktree', 'add', '--detach', str(worktree))
    return worktree


def run_script(cwd, fake_docker_path, docker_info):  # pragma: win32 no cover
    env = {
        **os.environ,
        'PATH': fake_docker_path,
        'FAKE_DOCKER_INFO': docker_info,
    }
    output = subprocess.check_output(
        (SCRIPT, 'some-image', 'some-hook', 'file.txt'),
        cwd=cwd,
        env=env,
        text=True,
    )
    return output.splitlines()


# Mounts

@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    'repo_fixture',
    (
        pytest.param('temp_git_dir', id='clone'),
        pytest.param('worktree_dir', id='worktree'),
    ),
)
def test_mounts_repo_and_git_dir(
        request, repo_fixture, temp_git_dir, fake_docker_path,
):
    repo_dir = os.path.realpath(request.getfixturevalue(repo_fixture))
    git_dir = os.path.realpath(temp_git_dir.join('.git'))

    args = run_script(repo_dir, fake_docker_path, ROOTFUL_INFO)

    assert args == [
        'run', '--rm',
        '-u', f'{os.getuid()}:{os.getgid()}',
        '-v', f'{repo_dir}:{repo_dir}:rw,Z',
        '-v', f'{git_dir}:{git_dir}:rw,Z',
        '--workdir', repo_dir,
        'some-image', 'some-hook', 'file.txt',
    ]


# User

@skip_win32  # pragma: win32 no cover
@pytest.mark.parametrize(
    ('docker_info', 'expected_has_user'),
    (
        pytest.param(ROOTFUL_INFO, True, id='rootful'),
        pytest.param(
            '{"SecurityOptions":["name=seccomp","name=rootless"]}',
            False,
            id='rootless-docker',
        ),
        pytest.param(
            '{"host":{"security":{"rootless":true}}}',
            False,
            id='rootless-podman',
        ),
    ),
)
def test_user_args(
        temp_git_dir, fake_docker_path, docker_info, expected_has_user,
):
    args = run_script(temp_git_dir, fake_docker_path, docker_info)

    assert ('-u' in args) == expected_has_user


# Hook config

def load_hooks():
    with open(os.path.join(REPO_DIR, '.pre-commit-hooks.yaml')) as f:
        return yaml.load(f)


def test_docker_hooks_use_script():
    for hook in load_hooks():
        if hook['language'] != 'fail':
            assert hook['language'] == 'script'
            assert hook['entry'].startswith('run-in-docker.sh ')


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
