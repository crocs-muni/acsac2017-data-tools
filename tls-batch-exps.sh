#!/bin/bash

HOMEDIR="/storage/praha1/home/$LOGNAME"
cd $HOMEDIR


qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00012.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00016.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00018.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00022.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00027.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00035.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00043.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00050.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00055.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00063.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00070.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00074.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00080.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00085.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00095.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00101.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00109.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00118.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00123.sh
qsub -l select=1:ncpus=1:mem=8gb:scratch_local=1gb -l walltime=48:00:00 ${HOMEDIR}/jobs-new/fullipv4-00124.sh


