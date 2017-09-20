import os

tpl = '''#!/bin/bash

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

exec stdbuf -eL python /storage/praha1/home/ph4r05/cas/codesign/censys_sonarssl_process.py \\
    --datadir /storage/brno3-cerit/home/ph4r05/eco_full \\
    --eco-json /storage/brno3-cerit/home/ph4r05/eco_full/eco.json \\
    --proc-total %s --proc-cur %s $@ 2> /storage/praha1/home/ph4r05/logs/process_eco_full_%02d.log 

'''

total_proc = 10
for i in range(total_proc):
    fname = 'sonar-eco-process-%02d.sh' % i
    with open(fname, 'w') as fh:
        fh.write(tpl % (total_proc, i, i))

with open('enqueue.sh', 'w') as fh:
    fh.write('#!/bin/bash\n\n')
    for i in range(total_proc):
        ram = 60 if i == 0 else 24
        fh.write('qsub -l select=1:ncpus=1:mem=%sgb:scratch_local=1gb:brno=True -l walltime=24:00:00 '
                 './sonar-eco-process-%02d.sh \n' % (ram, i))

os.system('chmod +x *.sh')




