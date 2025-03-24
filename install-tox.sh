#!/bin/bash
set -e
if command -V tox >/dev/null
then
    echo "tox is already installed"
else
    echo "Installing tox"
    mkdir -p ~/.local/bin/ ~/virtualenvs
    virtualenv ~/virtualenvs/tox
    . ~/virtualenvs/tox/bin/activate
    pip install tox
    deactivate
    ln -s ~/virtualenvs/tox/bin/tox ~/.local/bin/tox
fi
