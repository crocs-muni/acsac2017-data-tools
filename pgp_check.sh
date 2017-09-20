#!/bin/bash

HOMEDIR="/storage/praha1/home/${LOGNAME}"
cd $HOMEDIR

export MPICH_NEMESIS_NETMOD=tcp
export OMP_NUM_THREADS=$PBS_NUM_PPN
export PYENV_ROOT="${HOMEDIR}/.pyenv"
export PATH="${PYENV_ROOT}/bin:${PATH}"

# module add openmpi-2.0.1-intel
# module add openmpi-2.0.1-gcc
# module add openmpi

eval "$(pyenv init -)"
sleep 3

pyenv local 2.7.13
sleep 3

echo "`hostname` starting..."

exec stdbuf -eL python cas/codesign/pgp_check.py --debug --classif \
    --data /storage/brno3-cerit/home/ph4r05/pgp \
    --json /storage/brno3-cerit/home/mnemec/pgp-17-04-19/datasets/2017-04-19/merged.json \
    2> /storage/brno3-cerit/home/ph4r05/pgp/pgp_check.log \
    > /storage/brno3-cerit/home/ph4r05/pgp/pgp_check.out.log




