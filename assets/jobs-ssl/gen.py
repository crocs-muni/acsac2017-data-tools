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
    --datadir /storage/brno3-cerit/home/ph4r05/sonarssl \\
    --json /storage/praha1/home/ph4r05/cas/tls_sonar.ssl.json \\
    --proc-total %s --proc-cur %s $@ 2> /storage/praha1/home/ph4r05/logs/process_ssl_%02d.log 

'''

total_proc = 10
for i in range(total_proc):
    fname = 'sonar-ssl-process-%02d.sh' % i
    with open(fname, 'w') as fh:
        fh.write(tpl % (total_proc, i, i))

    with open('enqueue.sh', 'w') as fh:
        fh.write('#!/bin/bash\n\n')
        for i in range(total_proc):
            fh.write('qsub -l select=1:ncpus=1:mem=24gb:scratch_local=1gb:brno=True -l walltime=24:00:00 '
                     './sonar-ssl-process-%02d.sh \n' % i)

    os.system('chmod +x *.sh')







