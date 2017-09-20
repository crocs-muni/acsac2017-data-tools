#!/bin/bash

HOMEDIR="/storage/praha1/home/$LOGNAME"
cd $HOMEDIR

export PYENV_ROOT="$HOMEDIR/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
pyenv local 2.7.13

exec python cas/codesign/censys_tls.py $@

