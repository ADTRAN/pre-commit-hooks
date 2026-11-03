#!/usr/bin/env bash
set -eo pipefail

git_common_dir="$(cd "$(git rev-parse --git-common-dir)" && pwd -P)"
docker_info="$(docker info --format '{{json .}}')"

# Rootless docker/podman already map the container's root user to the host user
user_args=(-u "$(id -u):$(id -g)")
if [[ "${docker_info}" == *name=rootless* || "${docker_info}" == *'"rootless":true'* ]]; then
    user_args=()
fi

exec docker run --rm \
    "${user_args[@]}" \
    -v "${PWD}:${PWD}:rw,Z" \
    -v "${git_common_dir}:${git_common_dir}:rw,Z" \
    --workdir "${PWD}" \
    "$@"
