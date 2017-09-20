#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'dusanklinec'

from past.builtins import cmp
import argparse
import json
import os
import sys
import collections
import itertools
import traceback
import logging
import math
import base64
import utils
import coloredlogs
import time
import threading
from queue import Queue, Empty as QEmpty
import input_obj
import gzip
import gzipinputstream
from datetime import datetime
from newline_reader import NewlineReader, NewlineIterator


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class EcoRecode(object):
    """
    Processing censys http eco system dataset.
    Recodes dataset to regular snapshots. Generates json, dataset for classification.
    
    Script is designed to run on a big server with huge amount of RAM.
    One-pass, all in ram method.
    
    In case of optimisation is needed:
     - download big cert file to the disk, ungzip
     - do a sort on the fingerprints, disk sort
     - host file, one by one, download, disk sort, find fingerprints in the main big cert file.
    
    https://scans.io/study/umich-https
    """
    def __init__(self):
        self.args = None
        self.index_db = None

    def main(self):
        """
        Parameter processing
        :return:
        """
        parser = argparse.ArgumentParser(description='Processes Censys HTTP ecosystem dataset, generates incremental cert sets')

        parser.add_argument('--json', dest='json', default=None,
                            help='links json')

        parser.add_argument('--datadir', dest='datadir', default='.',
                            help='datadir')

        parser.add_argument('-t', '--threads', dest='threads', default=1, type=int,
                            help='certificate processing thread')

        parser.add_argument('--space', dest='space', default=False, action='store_const', const=True,
                            help='Keep at least 7 days spacing')

        args = parser.parse_args()
        self.args = args
        self.work()

    def work(self):
        """
        Processing
        :return: 
        """

        # Open the json link file
        args = self.args
        index_db = None
        with open(args.json, 'r') as fh:
            index_db = json.load(fh)
        self.index_db = index_db

        # Manage the raw_certificates file
        main_cert_rec = index_db['data'][1]
        main_cert_link = main_cert_rec['fhref']
        main_cert_file = os.path.join(args.datadir, os.path.basename(main_cert_link))
        json_res_file = os.path.join(args.datadir, 'eco.json')
        json_res_fh = open(json_res_file, 'w')

        iobj = None
        if os.path.exists(main_cert_file):
            iobj = input_obj.FileInputObject(fname=main_cert_file)

        elif os.path.exists(main_cert_file[:-3]):  # ungziped
            main_cert_file = main_cert_file[:-3]
            iobj = input_obj.FileInputObject(fname=main_cert_file)

        else:
            logger.info('Going to download certificate file')
            hosth = open(main_cert_file, 'wb')
            iobj = input_obj.ReconnectingLinkInputObject(url=main_cert_link, rec=main_cert_rec)
            iobj = input_obj.TeeInputObject(parent_fh=iobj, copy_fh=hosth, close_copy_on_exit=True)

        # Big in memory hash table fprint -> certificate
        bigdb = {}
        counter = 0
        testrng = range(15, 171)

        # fprints seen
        fprints_seen_set = set()
        fprints_previous = set()

        # Process the main certificate file
        with iobj:
            fh = iobj
            if main_cert_file.endswith('.gz'):
                fh = gzipinputstream.GzipInputStream(fileobj=iobj)
            else:
                fh = NewlineIterator(iobj)

            for idx, line in enumerate(fh):
                try:
                    csv = line.split(',')
                    fprint = utils.strip_hex_prefix(csv[0].strip())
                    cert = utils.strip_hex_prefix(csv[1].strip())

                    certbin = base64.b16decode(cert, True)
                    bigdb[fprint] = certbin
                    counter += 1

                    if counter % 100000 == 0:
                        logger.debug(' .. progress %s, fprint %s, memory: %s MB'
                                     % (counter, fprint, utils.get_mem_mb()))

                except Exception as e:
                    logger.error('Error in processing %s' % e)
                    logger.debug(traceback.format_exc())

        logger.info('Uff... big DB loaded, num entries: %s' % len(bigdb))

        # Load sequential scans
        # Host file association ip -> fingerprint
        jsdb_ids = {x['id']: x for x in self.index_db['data']}
        last_file_date_utc = 0
        for test_idx in testrng:
            filerec = jsdb_ids[test_idx]
            fname = filerec['fname']
            flink = filerec['fhref']
            datepart = filerec['date']
            date_utc = filerec['date_utc']
            fname_2 = os.path.basename(fname)

            # As dataset is in a form of snapshots we can skip some time intervals.
            if self.args.space and date_utc - last_file_date_utc < (60*60*24*7 - 60*60):
                logger.info('Skipping record %d, as the time diff is too small from the previous one: %s'
                            % (test_idx, date_utc - last_file_date_utc))
                continue

            last_file_date_utc = date_utc
            hostfile = os.path.join(args.datadir, fname_2)
            certfile = os.path.join(args.datadir, '%s_certs.gz' % datepart)
            fprintfile_new = os.path.join(args.datadir, '%s_fprints_new.csv' % datepart)
            fprintfile_new_p = os.path.join(args.datadir, '%s_fprints_new_p.csv' % datepart)
            fprintfile_lost_p = os.path.join(args.datadir, '%s_fprints_lost_p.csv' % datepart)

            js_res_rec = collections.OrderedDict()
            js_res_rec['fname'] = fname
            js_res_rec['fhref'] = flink
            js_res_rec['date'] = datepart
            js_res_rec['date_utc'] = date_utc
            js_res_rec['hostfile'] = hostfile
            js_res_rec['certfile'] = certfile
            js_res_rec['fprintfile_new'] = fprintfile_new
            js_res_rec['rec'] = filerec

            logger.info('Processing test idx %s, file %s' % (test_idx, fname))

            not_found = 0
            fprints_set = set()
            fprints_set_new = set()
            iobj = None
            hosth = None

            # Open local or open remote (with download to local)
            if os.path.exists(hostfile):
                iobj = input_obj.FileInputObject(fname=hostfile)
            else:
                hosth = open(hostfile, 'wb')
                iobj = input_obj.ReconnectingLinkInputObject(url=flink, rec=filerec)
                iobj = input_obj.TeeInputObject(parent_fh=iobj, copy_fh=hosth, close_copy_on_exit=True)

            # Processing ip -> fingerprints associations
            with iobj:
                fh = gzipinputstream.GzipInputStream(fileobj=iobj)
                for rec_idx, rec in enumerate(fh):
                    try:
                        linerec = rec.strip().split(',')
                        ip = linerec[0].strip()
                        fprint = utils.strip_hex_prefix(linerec[2].strip())
                        fprints_set.add(fprint)

                        if rec_idx % 1000000 == 0:
                            iobj.flush()
                            logger.debug(' .. progress %s, ip %s, mem: %s MB'
                                         % (rec_idx, ip, utils.get_mem_mb()))

                    except Exception as e:
                        logger.error('Exception in processing rec %s: %s' % (rec_idx, e))
                        logger.debug(rec)
                        logger.debug(traceback.format_exc())

            fprints_len = len(fprints_set)
            logger.info('File processed, fprint db size: %d' % fprints_len)

            # Only fingerprints
            logger.info('Going to sort fprints...')
            fprints = list(fprints_set)
            fprints.sort()
            logger.info('fprints sorted. Storing fingerprints. Mem: %s MB' % (utils.get_mem_mb()))

            # Store only new fingerprints, not seen before
            logger.info('Storing new fingerprints. Mem: %s MB' % (utils.get_mem_mb()))
            with open(fprintfile_new, 'w') as outfh:
                for fprint in fprints:
                    if fprint not in fprints_seen_set:
                        outfh.write('%s\n' % fprint)
                        fprints_set_new.add(fprint)
                        fprints_seen_set.add(fprint)

            # Certificates new from previous
            logger.info('Storing new fingerprints from previous. Mem: %s MB' % (utils.get_mem_mb()))
            with open(fprintfile_new_p, 'w') as outfh:
                for fprint in fprints:
                    if fprint not in fprints_previous:
                        outfh.write('%s\n' % fprint)

            # Certificates removed from previous
            logger.info('Storing lost fingerprints from previous. Mem: %s MB' % (utils.get_mem_mb()))
            fprints_previous_list = list(fprints_previous)
            fprints_previous_list.sort()

            with open(fprintfile_lost_p, 'w') as outfh:
                for fprint in fprints_previous_list:
                    if fprint not in fprints_set:
                        outfh.write('%s\n' % fprint)

            # Certificates file _certs.gz - only new certificates, incremental records
            fprints_new = list(fprints_set_new)
            fprints_new.sort()

            fprints_len = len(fprints_new)
            fprints_progress_unit = fprints_len / 100
            fprints_progress_last = 0
            logger.info('Dumping only new certificates, fprint db size: %d' % fprints_len)

            with gzip.open(certfile, 'wb') as outfh:
                for rec_idx, fprint in enumerate(fprints_new):

                    if fprints_progress_last + fprints_progress_unit < rec_idx:
                        fprints_progress_last = rec_idx
                        outfh.flush()
                        logger.debug(' .. progress %s, mem: %s MB'
                                     % (rec_idx, utils.get_mem_mb()))

                    if fprint in bigdb:
                        outfh.write('%s,%s\n' % (fprint, base64.b64encode(bigdb[fprint])))

                    else:
                        not_found += 1

            logger.info('Finished with idx %s, file %s, newfile: %s, not found: %s, mem: %s MB'
                        % (test_idx, fname, certfile, not_found, utils.get_mem_mb()))

            # Final step - store to previous
            fprints_previous = set(fprints_set)

            # Result file record flush
            json_res_fh.write(json.dumps(js_res_rec) + '\n')
            json_res_fh.flush()

        json_res_fh.close()


if __name__ == '__main__':
    EcoRecode().main()




