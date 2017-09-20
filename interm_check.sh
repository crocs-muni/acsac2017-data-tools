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

mkdir -p interm2
exec stdbuf -eL -oL python cas2/codesign/interm_build.py \
    --tlsdir /storage/brno3-cerit/home/ph4r05/fulltls/ \
    --alexa /storage/brno3-cerit/home/ph4r05/alexa/ \
    --sonar-snap /storage/brno3-cerit/home/ph4r05/sonarssl/ /storage/brno3-cerit/home/ph4r05/eco_full/ \
    --data interm2 \
    --debug --sec 2>&1 | tee intern-out2.log

