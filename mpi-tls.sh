#!/bin/bash

DATADIR="/storage/praha1/home/$LOGNAME/results2"
HOMEDIR="/storage/praha1/home/$LOGNAME"
cd $HOMEDIR

export PYENV_ROOT="$HOMEDIR/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
pyenv local 2.7.13

export OMP_NUM_THREADS=$PBS_NUM_PPN
module avail 2>&1 | tr ' ' '\n' | egrep -i '^openmpi|^m[v]*[a]*pich'|sort

mpirun -machinefile $PBS_NODEFILE stdbuf -eL /storage/praha1/home/ph4r05/cas/censys_tls_wrapper.sh \
    --debug --link-file "/storage/praha1/home/ph4r05/cas/tls_ipv4_history.json" \
    --link-idx 11 20 30 40 50 60 70 80 90 100 110 120 \
    --data "/storage/praha1/home/ph4r05/results2" --continue --mpi

mpirun -machinefile $PBS_NODEFILE stdbuf -eL /storage/praha1/home/ph4r05/cas/censys_tls_wrapper.sh \
    --debug --link-file "/storage/praha1/home/ph4r05/cas/tls_ipv4_history.json" \
    --link-idx 11 20 30 40 50 60 70 80 90 100 110 120 \
    --data "/storage/praha1/home/ph4r05/results2" --continue --mpi


stdbuf -eL /storage/praha1/home/ph4r05/cas/censys_tls_mpi_wrapper.sh \
    --debug --link-file "/storage/praha1/home/ph4r05/cas/tls_ipv4_history.json" \
    --link-idx 11 20 30 40 50 60 70 80 90 100 110 120 \
    --data "/storage/praha1/home/ph4r05/results2" --continue --mpi


mpirun -machinefile $PBS_NODEFILE python /storage/praha1/home/ph4r05/cas/codesign/censys_tls.py \
    --debug --link-file "/storage/praha1/home/ph4r05/cas/tls_ipv4_history.json" \
    --link-idx 11 20 30 40 50 60 70 80 90 100 110 120 \
    --data "/storage/praha1/home/ph4r05/results2" --continue --mpi

mpirun -machinefile $PBS_NODEFILE -- /storage/praha1/home/ph4r05/cas/censys_tls_wrapper.sh \
    --debug --link-file "/storage/praha1/home/ph4r05/cas/tls_ipv4_history.json"     \
    --link-idx 11 20 30 40 50 60 70 80 90 100 110 120    \
    --data "/storage/praha1/home/ph4r05/results2" --continue --mpi


mpirun --mca 'btl ^openib' -machinefile $PBS_NODEFILE -- /storage/praha1/home/ph4r05/cas/censys_tls_wrapper.sh \
    --debug --link-file "/storage/praha1/home/ph4r05/cas/tls_ipv4_history.json"     \
    --link-idx 11 20 30 40 50 60 70 80 90 100 110 120    \
    --data "/storage/praha1/home/ph4r05/results2" --continue --mpi


#2>> "/storage/praha1/home/ph4r05/logs/5889_060.log"