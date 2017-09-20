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

#exec stdbuf -eL python cas2/codesign/censys_tls_sec.py --debug \
#    --data /storage/brno3-cerit/home/ph4r05/allcert/  \
#    --file /storage/brno3-cerit/home/ph4r05/data/9b9tbkx9758vh7ew-certificates.20170412T045214.json.lz4 \
#    2> /storage/praha1/home/ph4r05/logs/tls-allcert.log

exec stdbuf -eL python cas2/codesign/censys_tls_sec.py --debug \
    --data /storage/brno3-cerit/home/ph4r05/allcert/  \
    --url https://scans.io/zsearch/dxhq71ztrfbycs2b-certificates.20170521T053446.json.lz4 \
    2> /storage/praha1/home/ph4r05/logs/tls-allcert2.log




