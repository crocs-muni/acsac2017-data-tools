#!/bin/bash

DIR=$1
if [ -z "$DIR" ]; then
    echo "Usage: $0 dir"
    exit 1
fi

for i in `ls ${DIR}/*.json`; do
    CFILE="${i}"
    cat $CFILE >> /storage/brno3-cerit/home/ph4r05/eeids-total/eeids_total.json
done
