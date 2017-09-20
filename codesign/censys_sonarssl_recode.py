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
import input_obj
import gzip
import gzipinputstream
from datetime import datetime
from trace_logger import Tracelogger

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class Recode(object):
    def __init__(self):
        self.trace_logger = Tracelogger()

    def main(self):
        """
        Processing censys sonar.ssl
        Recodes one big certificate file to smaller _certs.gz files as published since 2015
        so we can process it in the same way.
        
        https://scans.io/study/sonar.ssl
        :return:
        """
        parser = argparse.ArgumentParser(description='Processes Censys links from the page, generates json')

        parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='censys links')

        parser.add_argument('--json', dest='json', default=None,
                            help='sonar links json')

        parser.add_argument('--datadir', dest='datadir', default='.',
                            help='datadir')

        parser.add_argument('--fprint-only', dest='fprint_only', default=False, action='store_const', const=True,
                            help='Only fprint gen')

        parser.add_argument('--base-only', dest='base_only', default=False, action='store_const', const=True,
                            help='Chunk only one big dataset sample')

        parser.add_argument('file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='censys link file')

        args = parser.parse_args()

        # Big in memory hash table fprint -> certificate
        bigdb = {}
        testrng = range(10, 93) if args.base_only else range(10, 181)

        # fprints seen
        fprints_seen_set = set()
        fprints_previous = set()

        if not args.fprint_only:
            if len(args.file) == 0:
                return
            main_file = args.file[0]
            self.load_cert_db(main_file, bigdb)

        jsdb = None
        with open(args.json, 'r') as fh:
            jsdb = json.load(fh)

        jsdb_ids = {x['id']: x for x in jsdb['data']}
        for test_idx in testrng:
            files = jsdb_ids[test_idx]['files']
            filerec = None
            for tmprec in files:
                if '_hosts.gz' in tmprec:
                    filerec = files[tmprec]
                    break

            fname = filerec['name']
            flink = filerec['href']

            # 20131104/20131104_hosts.gz
            fname_2 = fname.split('/')
            if len(fname_2) == 2:
                fname_2 = fname_2[1]
            else:
                fname_2 = fname_2[0]

            dateparts = fname_2.split('_')
            datepart = dateparts[0]

            hostfile = os.path.join(args.datadir, '%s_hosts.gz' % datepart)
            certfile = os.path.join(args.datadir, '%s_certs.gz' % datepart)
            fprintfile = os.path.join(args.datadir, '%s_fprints.csv' % datepart)
            fprintfile_new = os.path.join(args.datadir, '%s_fprints_new.csv' % datepart)
            fprintfile_new_p = os.path.join(args.datadir, '%s_fprints_new_p.csv' % datepart)
            fprintfile_lost_p = os.path.join(args.datadir, '%s_fprints_lost_p.csv' % datepart)
            fprintfile_same = os.path.join(args.datadir, '%s_fprints_same.csv' % datepart)
            logger.info('Processing test idx %s, file %s, newfile: %s' % (test_idx, fname, certfile))

            not_found = 0
            fprints_set = set()
            fprints_set_new = set()
            iobj = None
            hosth = None

            if os.path.exists(hostfile):
                iobj = input_obj.FileInputObject(fname=hostfile)

            elif args.fprint_only:
                continue

            else:
                hosth = open(hostfile, 'wb')
                iobj = input_obj.ReconnectingLinkInputObject(url=flink, rec=files)
                iobj = input_obj.TeeInputObject(parent_fh=iobj, copy_fh=hosth, close_copy_on_exit=True)

            # Reading host file, ip -> fprints associations
            with iobj:
                fh = gzipinputstream.GzipInputStream(fileobj=iobj)
                for rec_idx, rec in enumerate(fh):
                    try:

                        linerec = rec.strip().split(',')
                        ip = linerec[0].strip()
                        fprints = linerec[1:]
                        for fprint in fprints:
                            fprint = utils.strip_hex_prefix(fprint.strip()).lower()
                            fprints_set.add(fprint)

                        if rec_idx % 1000000 == 0:
                            iobj.flush()
                            logger.debug(' .. progress %s, ip %s, mem: %s MB'
                                         % (rec_idx, ip, utils.get_mem_usage() / 1024.0))

                    except Exception as e:
                        logger.error('Exception in processing rec %s: %s' % (rec_idx, e))
                        logger.debug(rec)
                        logger.debug(traceback.format_exc())

            fprints_len = len(fprints_set)
            logger.info('File processed, fprint db size: %d. Mem: %s MB' % (fprints_len, utils.get_mem_mb()))

            # Only fingerprints
            logger.info('Going to sort fprints...')
            fprints = list(fprints_set)
            fprints.sort()
            logger.info('fprints sorted. Storing fingerprints. Mem: %s MB' % (utils.get_mem_usage() / 1024.0))

            # Store only new fingerprints, not seen before
            logger.info('Storing new fingerprints. Mem: %s MB' % (utils.get_mem_usage() / 1024.0))
            with open(fprintfile_new, 'w') as outfh:
                for fprint in fprints:
                    if fprint not in fprints_seen_set:
                        outfh.write('%s\n' % fprint)
                        fprints_set_new.add(fprint)
                        fprints_seen_set.add(fprint)

            # Certificates new from previous
            logger.info('Storing new fingerprints from previous. Mem: %s MB' % (utils.get_mem_usage() / 1024.0))
            with open(fprintfile_new_p, 'w') as outfh:
                for fprint in fprints:
                    if fprint not in fprints_previous:
                        outfh.write('%s\n' % fprint)

            # Certificates removed from previous
            logger.info('Storing lost fingerprints from previous. Mem: %s MB' % (utils.get_mem_usage() / 1024.0))
            fprints_previous_list = list(fprints_previous)
            fprints_previous_list.sort()

            with open(fprintfile_lost_p, 'w') as outfh:
                for fprint in fprints_previous_list:
                    if fprint not in fprints_set:
                        outfh.write('%s\n' % fprint)

            # Certificates same as in the previous dataset
            logger.info('Storing same fingerprints as previous. Mem: %s MB' % (utils.get_mem_usage() / 1024.0))
            with open(fprintfile_same, 'w') as outfh:
                for fprint in fprints:
                    if fprint in fprints_previous:
                        outfh.write('%s\n' % fprint)

            # Store only fingerprints contained in this set.
            with open(fprintfile, 'w') as outfh:
                for fprint in fprints:
                    outfh.write('%s\n' % fprint)

            if args.fprint_only:
                fprints_previous = set(fprints_set)
                continue

            # Certificates file _certs.gz - only new certificates
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
                                     % (rec_idx, utils.get_mem_usage() / 1024.0))

                    if fprint in bigdb:
                        outfh.write('%s,%s\n' % (fprint, base64.b64encode(bigdb[fprint])))

                    else:
                        not_found += 1

            logger.info('Finished with idx %s, file %s, newfile: %s, not found: %s, mem: %s MB'
                        % (test_idx, fname, certfile, not_found, utils.get_mem_usage() / 1024.0))

            # Final step - store to previous
            fprints_previous = set(fprints_set)

    def load_cert_db(self, main_file, bigdb):
        """
        Loads big fprint -> certificate database to memory
        :param main_file: 
        :param bigdb: 
        :return: 
        """
        counter = 0
        # Open the main file, gziped or not
        if main_file.endswith('gz'):
            fh = gzip.open(main_file, 'rb')
        else:
            fh = open(main_file, 'rb')

        errors = 0
        with fh:
            for idx, line in enumerate(fh):
                try:
                    fprint, cert = line.split(',', 1)
                    cert = cert.strip()
                    fprint = utils.strip_hex_prefix(fprint.strip()).lower()

                    certbin = base64.b64decode(cert)
                    bigdb[fprint] = certbin
                    counter += 1

                    if counter % 10000 == 0:
                        logger.debug(' .. progress %s, fprint %s, memory: %s MB'
                                     % (counter, fprint, utils.get_mem_usage() / 1024.0))

                except Exception as e:
                    errors += 1
                    logger.error('Error in processing %s' % e)
                    self.trace_logger.log(e)

        logger.info('Uff... big DB loaded, num entries: %s, errors: %s, memory: %s MB'
                    % (len(bigdb), errors, utils.get_mem_mb()))


if __name__ == '__main__':
    cls = Recode()
    cls.main()






