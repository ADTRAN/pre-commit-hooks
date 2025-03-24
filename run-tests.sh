#!/bin/bash
set -ex
tox -e pre-commit
tox -e check
tox -e py38 -- -vvl
tox -e py39 -- -vvl
tox -e py310 -- -vvl
tox -e py311 -- -vvl
tox -e py312 -- -vvl
