#!/usr/bin/env python3
# Adapted from pre-commit's languages/docker.py to mount the working directory
# and the main .git dir at their own paths, so git worktrees work
from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import sys

_HOSTNAME_MOUNT_RE = re.compile(
    rb"""
    /containers
    (?:/overlay-containers)?
    /([a-z0-9]{64})
    (?:/userdata)?
    /hostname
    """,
    re.VERBOSE,
)


def _get_container_id() -> str | None:  # pragma: win32 no cover
    with contextlib.suppress(FileNotFoundError):
        with open('/proc/1/mountinfo', 'rb') as f:
            for line in f:
                m = _HOSTNAME_MOUNT_RE.search(line)
                if m:
                    return m[1].decode()

    return None


def _get_docker_path(path: str) -> str:  # pragma: win32 no cover
    container_id = _get_container_id()
    if container_id is None:
        return path

    proc = subprocess.run(
        ('docker', 'inspect', container_id),
        capture_output=True,
    )
    if proc.returncode != 0:
        # self-container was not visible from here (perhaps docker-in-docker)
        return path

    container, = json.loads(proc.stdout)
    for mount in container['Mounts']:
        src_path = mount['Source']
        to_path = mount['Destination']
        if os.path.commonpath((path, to_path)) == to_path:
            # So there is something in common,
            # and we can proceed remapping it
            return path.replace(to_path, src_path)
    # we're in Docker, but the path is not mounted, cannot really do anything,
    # so fall back to original path
    return path


def _is_rootless() -> bool:  # pragma: win32 no cover
    proc = subprocess.run(
        ('docker', 'system', 'info', '--format', '{{ json . }}'),
        capture_output=True,
    )
    if proc.returncode != 0:
        return False

    info = json.loads(proc.stdout)
    try:
        return (
            # docker:
            # https://docs.docker.com/reference/api/engine/version/v1.48/#tag/System/operation/SystemInfo
            'name=rootless' in (info.get('SecurityOptions') or ()) or
            # podman:
            # https://docs.podman.io/en/latest/_static/api.html?version=v5.4#tag/system/operation/SystemInfoLibpod
            info['host']['security']['rootless']
        )
    except KeyError:
        return False


def get_docker_user() -> tuple[str, ...]:  # pragma: win32 no cover
    if _is_rootless():
        return ()

    return ('-u', f'{os.getuid()}:{os.getgid()}')


def _get_git_common_dir() -> str:  # pragma: win32 no cover
    out = subprocess.check_output(
        ('git', 'rev-parse', '--git-common-dir'),
        text=True,
    )
    return os.path.realpath(out.strip())


def get_docker_tty() -> tuple[str, ...]:  # pragma: win32 no cover
    # pre-commit runs hooks in a pseudo-terminal when color is on
    return (('--tty',) if sys.stdout.isatty() else ())


def docker_cmd() -> tuple[str, ...]:  # pragma: win32 no cover
    cwd = os.getcwd()
    git_common_dir = _get_git_common_dir()
    return (
        'docker', 'run',
        '--rm',
        *get_docker_tty(),
        *get_docker_user(),
        # https://docs.docker.com/engine/reference/commandline/run/#mount-volumes-from-container-volumes-from
        # The `Z` option tells Docker to label the content with a private
        # unshared label. Only the current container can use a private volume.
        '-v', f'{_get_docker_path(cwd)}:{cwd}:rw,Z',
        '-v', f'{_get_docker_path(git_common_dir)}:{git_common_dir}:rw,Z',
        '--workdir', cwd,
    )


def main() -> int:  # pragma: win32 no cover
    return subprocess.call((*docker_cmd(), *sys.argv[1:]))


if __name__ == '__main__':
    raise SystemExit(main())
