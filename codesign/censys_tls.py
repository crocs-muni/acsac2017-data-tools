#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pkg_resources
import logging
import coloredlogs
import sys
import argparse
import os
import json
import re
import utils
import traceback
import collections
import datetime
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
import base64
import time

import input_obj
import lz4framed
import newline_reader


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)

tags = utils.enum('READY', 'DONE', 'EXIT', 'START')


def get_backend(backend=None):
    return default_backend() if backend is None else backend


class DecompressorCheckpoint(object):
    """
    Represents simple point in the data stream for random access read.
    """

    def __init__(self, pos, rec_pos=None, plain_pos=None, ctx=None, *args, **kwargs):
        """
        New checkpoint    
        :param pos: position in the compressed stream (on the input) - seekable position for random access.
        :param rec_pos: position in the decompressed stream, newline separated. record boundary
        :param plain_pos: position in the decompressed stream, decompressed chunk >= rec_pos
        :param ctx: decompressor context
        :param args: 
        :param kwargs: 
        """
        self.pos = pos
        self.rec_pos = rec_pos
        self.plain_pos = plain_pos
        self.ctx = ctx

    def to_json(self):
        js = collections.OrderedDict()
        js['pos'] = self.pos
        js['rec_pos'] = self.rec_pos
        js['plain_pos'] = self.plain_pos
        js['ctx'] = base64.b64encode(self.ctx) if self.ctx is not None else None
        return js


class CensysTls(object):
    """
    Downloading & processing of the Censys data
    """

    def __init__(self):
        self.args = None
        self.fmagic = None
        self.chain_cert_db = {}

        self.link_idx_offset = 0
        self.input_objects = []

        # Current state
        self.not_tls = 0
        self.not_cert_ok = 0
        self.not_chain_ok = 0
        self.not_parsed = 0
        self.not_rsa = 0

        self.loaded_checkpoint = None
        self.read_data = 0
        self.last_report = 0
        self.ctr = 0
        self.chain_ctr = 0
        self.cur_state_file = None
        self.cur_decompressor = None
        self.processor = None
        self.file_leafs_fh = None
        self.file_roots_fh = None
        self.last_record_resumed = None
        self.last_record_seen = None
        self.last_record_flushed = None
        self.decompressor_checkpoints = {}
        self.state_loaded_ips = set()

    def load_roots(self):
        """
        Loads root certificates
        File downloaded from: https://curl.haxx.se/docs/caextract.html
        :return: 
        """

        resource_package = __name__
        resource_path = 'data/cacert.pem'
        return pkg_resources.resource_string(resource_package, resource_path)

    def is_dry(self):
        """
        Returns true if dry run
        :return: 
        """
        return self.args.dry_run

    def process_mpi(self):
        """
        MPI processing worker / manager.
        :return: 
        """
        # noinspection PyUnresolvedReferences
        from mpi4py import MPI

        comm = MPI.COMM_WORLD  # get MPI communicator object
        size = comm.size  # total number of processes
        rank = comm.rank  # rank of this process
        status = MPI.Status()  # get MPI status object
        # logger.info('MPI, size: %02d, rank: %02d, status: %s' % (size, rank, status))

        # Manager of the pool
        if rank == 0:
            task_index = 0
            num_workers = size - 1
            closed_workers = 0
            ready_workers_set = set()
            logger.info('Master starting with %d workers, task set size: %s' % (num_workers, len(self.input_objects)))
            while closed_workers < num_workers:
                data = comm.recv(source=MPI.ANY_SOURCE, tag=MPI.ANY_TAG, status=status)
                source = status.Get_source()
                tag = status.Get_tag()

                if tag == tags.READY:
                    # Worker is ready, so send it a task
                    if task_index < len(self.input_objects):
                        comm.send(task_index, dest=source, tag=tags.START)
                        logger.info('Sending task %d to worker %d' % (task_index, source))
                        task_index += 1
                    else:
                        logger.info('Worker %s has no more jobs to run' % source)
                        comm.send(None, dest=source, tag=tags.EXIT)

                elif tag == tags.DONE:
                    results = data
                    logger.info('Got data from worker %d' % source)

                elif tag == tags.EXIT:
                    logger.info('Worker %d exited.' % source)
                    closed_workers += 1

            logger.info('Master finishing')
        else:
            # Worker processes execute code below
            name = MPI.Get_processor_name()
            logger.info('I am a worker with rank %d on %s.' % (rank, name))

            while True:
                comm.send(None, dest=0, tag=tags.READY)
                logger.info('Subscribed!')

                iobj_idx = comm.recv(source=0, tag=MPI.ANY_TAG, status=status)
                tag = status.Get_tag()

                # Do the work here
                if tag == tags.START:
                    try:
                        iobj = self.input_objects[iobj_idx]
                        logger.info('Processing idx=%02d, %s ' % (iobj_idx, iobj))
                        self.process_iobj(iobj)
                    except Exception as e:
                        logger.error('Exception when processing IOBJ: %s, %s' % (iobj, e))
                        logger.info('Progress: %s' % self.ctr)
                        logger.debug(traceback.format_exc())

                    comm.send(iobj_idx, dest=0, tag=tags.DONE)

                elif tag == tags.EXIT:
                    break

            comm.send(None, dest=0, tag=tags.EXIT)

    def process(self):
        """
        Process all input objects.
        :return: 
        """
        for iobj in self.input_objects:
            try:
                self.process_iobj(iobj)
            except Exception as e:
                logger.error('Exception when processing IOBJ: %s, %s' % (iobj, e))
                logger.info('Progress: %s' % self.ctr)
                logger.debug(traceback.format_exc())

    def iobj_name(self, iobj):
        """
        Tries to determine experiment name from the input object
        example: p6p0lbheekv0cwdz-443-https-tls-full_ipv4-20170323T023003-zgrab-log.log.lz4
        :param iobj: 
        :return: 
        """
        name = str(iobj)
        try:
            name = os.path.basename(name)
            match = re.match(r'^([a-zA-Z0-9]+)-443-', name)

            if match:
                sub = match.group(1)
                name = name.replace(sub + '-', '')

        except Exception as e:
            logger.error('Error in determining experiment name %s' % e)
            logger.info(traceback.format_exc())

        return name

    def get_finish_file(self, name):
        """
        Returns path to the finish indicator file
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.finished')

    def get_state_file(self, name):
        """
        Returns path to the state file with progress & resumption data
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.state.json')

    def get_classification_leafs(self, name):
        """
        Returns path to the json classification file for leafs 
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.cl.json')

    def get_classification_roots(self, name):
        """
        Returns path to the json classification file for leafs 
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.cr.json')

    def continue_roots(self):
        """
        Read roots line by line, build chain database.
        Find the last valid record, remove on that one.
        :return: 
        """

        pos = 0
        invalid_record = False

        for line in self.file_roots_fh:
            ln = len(line)
            try:
                js = json.loads(line)
                self.chain_cert_db[js['fprint']] = js['id']
                self.chain_ctr = max(self.chain_ctr, js['id'])
                pos += ln

            except Exception as e:
                invalid_record = True
                break

        logger.info('Operation resumed at chain ctr: %s, total chain records: %s'
                    % (self.chain_ctr, len(self.chain_cert_db)))

        if invalid_record:
            logger.info('Roots: Invalid record detected, position: %s' % pos)

            if not self.is_dry():
                self.file_roots_fh.seek(pos)
                self.file_roots_fh.truncate()
                self.file_roots_fh.flush()

    def continue_leafs(self, name):
        """
        Continues processing of the leafs.
        Finds the last record - returns this also.
        Truncates the rest of the file.
        :param name: 
        :return: last record loaded
        """
        fsize = os.path.getsize(name)
        pos = 0

        # If file is too big try to skip 10 MB before end
        if fsize > 1024*1024*1024*2:
            pos = fsize - 1024*1024*1024*1.5
            logger.info('Leafs file too big: %s, skipping to %s' % (fsize, pos))

            self.file_leafs_fh.seek(pos)
            x = self.file_leafs_fh.next()  # skip unfinished record
            pos += len(x)

        record_from_state_found = False
        terminate_with_record = False
        last_record = None
        last_id_seen = None
        for line in self.file_leafs_fh:
            ln = len(line)
            try:
                last_record = json.loads(line)
                last_id_seen = last_record['id']
                self.state_loaded_ips.add(last_record['ip'])
                self.ctr = max(self.ctr, last_record['id'])
                pos += ln

                if self.last_record_flushed is not None and self.last_record_flushed['ip'] == last_record['ip']:
                    logger.info('Found last record flushed in data file, ip: %s' % last_record['ip'])
                    record_from_state_found = True
                    break

            except Exception as e:
                terminate_with_record = True
                break

        logger.info('Operation resumed at leaf ctr: %s, last ip: %s'
                    % (self.ctr, utils.defvalkey(last_record, 'ip')))

        if self.last_record_flushed is not None and not record_from_state_found:
            logger.warning('Could not find the record from the state in the data file. Some data may be missing.')
            logger.info('Last record from state id: %s, last record data file id: %s'
                        % (self.last_record_resumed['id'], last_id_seen))
            raise ValueError('Incomplete data file')

        if terminate_with_record:
            logger.info('Leaf: Invalid record detected, position: %s' % pos)

            if not self.is_dry():
                self.file_leafs_fh.seek(pos)
                self.file_leafs_fh.truncate()
                self.file_leafs_fh.flush()

        return last_record

    def try_store_checkpoint(self, iobj, idx=None, resume_idx=None, resume_token=None):
        """
        Try-catch store checkpoint to handle situations when files cannot be flushed.
        In that case checkpoint cannot be stored, otherwise we won't be able to restore it properly.
        :param iobj: 
        :param idx: 
        :param resume_idx: 
        :param resume_token: 
        :return: 
        """
        attempts = 0
        while True:
            try:
                return self.store_checkpoint(iobj, idx, resume_idx, resume_token)

            except Exception as e:
                logger.error('Exception in storing a checkpoint %d: %s' % (attempts, e))
                logger.debug(traceback.format_exc())
                attempts += 1
                time.sleep(15)

    def store_checkpoint(self, iobj, idx=None, resume_idx=None, resume_token=None):
        """
        Stores checkpoint for the current input object
        :param iobj: 
        :param idx: 
        :param resume_idx: 
        :param resume_token: 
        :return: 
        """
        state_file = self.cur_state_file
        if self.is_dry():
            state_file += '.dry'

        input_name = self.iobj_name(iobj)

        # Most importantly, flush data file buffers now so the state is in sync with the checkpoint.
        self.file_leafs_fh.flush()
        self.file_roots_fh.flush()

        js = collections.OrderedDict()
        js['iobj_name'] = input_name
        js['time'] = time.time()
        js['read_raw'] = self.read_data
        js['block_idx'] = idx
        js['ctr'] = self.ctr
        js['chain_ctr'] = self.chain_ctr
        js['resume_idx'] = resume_idx
        js['resume_token'] = resume_token

        # Serialize input object state
        js['iobj'] = iobj.to_state()
        js['loaded_checkpoint'] = self.loaded_checkpoint

        # New decompressor checkpoint for random access read
        if self.cur_decompressor is not None and self.cur_decompressor.last_read_aligned:
            try:
                total_read_dec = self.cur_decompressor.data_read
                decctx = lz4framed.marshal_decompression_context(self.cur_decompressor.ctx)
                logger.debug('Decompressor state marshalled, size: %s B' % len(decctx))

                checkpoint = DecompressorCheckpoint(pos=total_read_dec, rec_pos=self.read_data,
                                                    plain_pos=self.processor.total_len, ctx=decctx)

                self.decompressor_checkpoints[total_read_dec] = checkpoint

                decctx_str = base64.b16encode(decctx)
                js['dec_ctx'] = decctx_str

            except Exception as e:
                logger.error('Exception when storing decompressor state: %s' % e)
                logger.warning(traceback.format_exc())

        js['dec_checks'] = [x.to_json() for x in self.decompressor_checkpoints.values()]

        # Last seen record
        js['last_record_seen'] = self.last_record_seen
        js['last_record_flushed'] = self.last_record_flushed

        utils.flush_json(js, state_file)

    def restore_checkpoint(self, iobj):
        """
        Tries to restore the checkpoint
        :param iobj: 
        :return: 
        """
        state_file = self.cur_state_file
        input_name = self.iobj_name(iobj)
        if not os.path.exists(state_file):
            logger.info('No checkpoint found for %s' % input_name)
            return

        logger.info('Trying to restore the checkpoint %s for %s' % (state_file, input_name))

        # backup checkpoint so it is not overwritten by invalid state
        utils.file_backup(state_file)

        with open(state_file, 'r') as fh:
            js = json.load(fh)
            if 'read_raw' not in js or 'iobj' not in js or 'data_read' not in js['iobj']:
                raise ValueError('State file is invalid')

            offset = js['iobj']['data_read'] + utils.intval(js['iobj']['start_offset'])
            self.read_data = js['read_raw']

            logger.info('Restoring checkpoint, offset: %s, read_data: %s' % (offset, self.read_data))
            iobj.start_offset = offset

            self.loaded_checkpoint = js

            if 'dec_checks' in js:
                self.decompressor_checkpoints = {
                    x['pos']: DecompressorCheckpoint(pos=x['pos'], rec_pos=x['rec_pos'],
                                                     plain_pos=x['plain_pos'], ctx=x['ctx'])
                    for x in js['dec_checks']
                }

            if 'last_record_seen' in js:
                self.last_record_resumed = js['last_record_seen']

            if 'last_record_flushed' in js:
                self.last_record_flushed = js['last_record_flushed']

            if self.cur_decompressor is not None and 'dec_ctx' in js:
                logger.info('Restoring decompressor state')
                decctx_str = base64.b16decode(js['dec_ctx'])
                decctx = lz4framed.unmarshal_decompression_context(decctx_str)
                self.cur_decompressor.setctx(decctx)
                self.loaded_checkpoint['dec_ctx'] = None

        logger.info('Decompressor checkpoint restored for %s' % input_name)

    def process_iobj(self, iobj):
        """
        Processing
        :param iobj: 
        :return: 
        """
        input_name = self.iobj_name(iobj)
        logger.info('Processing: %s' % input_name)

        finish_file = self.get_finish_file(input_name)
        if os.path.exists(finish_file):
            logger.info('Finish indicator file exists, skipping: %s' % finish_file)
            return

        self.cur_decompressor = None
        self.cur_state_file = self.get_state_file(input_name)
        file_leafs = self.get_classification_leafs(input_name)
        file_roots = self.get_classification_roots(input_name)
        self.last_record_resumed = None

        self.processor = newline_reader.NewlineReader(is_json=False)
        handle = iobj
        name = str(iobj)

        if name.endswith('lz4'):
            self.cur_decompressor = lz4framed.Decompressor(handle)
            handle = self.cur_decompressor

        if not self.is_dry() and (not self.args.continue1
                                  or not os.path.exists(file_leafs)
                                  or not os.path.exists(file_roots)):
            utils.safely_remove(file_leafs)
            utils.safely_remove(file_roots)
            self.file_leafs_fh = utils.safe_open(file_leafs, mode='w', chmod=0o644)
            self.file_roots_fh = utils.safe_open(file_roots, mode='w', chmod=0o644)

        elif self.args.continue1:
            logger.info('Continuing with the started files')
            self.file_leafs_fh = open(file_leafs, mode='r+' if not self.is_dry() else 'r')
            self.file_roots_fh = open(file_roots, mode='r+' if not self.is_dry() else 'r')
            self.restore_checkpoint(iobj)
            self.continue_roots()
            self.continue_leafs(file_leafs)

        with iobj:
            resume_token_found = False
            resume_token = None
            resume_idx = 0
            record_ctr = -1
            already_processed = 0
            read_start = self.read_data
            for idx, record in self.processor.process(handle):
                try:
                    record_ctr += 1
                    self.read_data += len(record)

                    # Check the checkpoint distance + boundary - process all newline chunks available
                    if self.read_data - self.last_report >= 1024*1024*1024 and self.processor.step_cur_last_element:
                        logger.info('...progress: %s GB, idx: %s, pos: %s GB, mem: %04.8f MB, readpos: %s (%4.6f GB)'
                                    % (self.read_data/1024.0/1024.0/1024.0, idx, self.read_data,
                                       utils.get_mem_mb(), iobj.tell(), iobj.tell()/1024.0/1024.0/1024.0))

                        self.last_report = self.read_data
                        self.try_store_checkpoint(iobj=iobj, idx=idx, resume_idx=resume_idx, resume_token=resume_token)

                        # Flush already seen IP database, not needed anymore
                        # we are too far from the resumed checkpoint
                        if read_start + 1024*1024*1024*2 > self.read_data:
                            self.state_loaded_ips = set()

                    js = json.loads(record)

                    # If there are more records after the last checkpoint load, skip duplicates
                    if js['ip'] in self.state_loaded_ips:
                        already_processed += 1
                        continue

                    self.process_record(idx, js)

                except Exception as e:
                    logger.error('Exception in processing %d: %s' % (self.ctr, e))
                    logger.debug(traceback.format_exc())
                    logger.debug(record)

                self.ctr += 1

            logger.info('Total: %d' % self.ctr)
            logger.info('Total_chain: %d' % self.chain_ctr)
            logger.info('Not tls: %d' % self.not_tls)
            logger.info('Not cert ok: %d' % self.not_cert_ok)
            logger.info('Not chain ok: %d' % self.not_chain_ok)
            logger.info('Not parsed: %d' % self.not_parsed)
            logger.info('Not rsa: %d' % self.not_rsa)

        logger.info('Processed: %s' % iobj)
        if not self.is_dry():
            self.file_leafs_fh.close()
            self.file_roots_fh.close()
            utils.try_touch(finish_file)

    def is_record_tls(self, record):
        """
        Returns true if contains server_certificates
        :param record: 
        :return: 
        """
        if 'data' not in record:
            # logger.info('No data for %s' % domain)
            return False

        if 'tls' not in record['data']:
            # logger.info('No tls for %s' % domain)
            return False

        if 'server_certificates' not in record['data']['tls']:
            # logger.info('No server_certificates for %s' % domain)
            return False

        return True

    def fill_rsa_ne(self, ret, parsed):
        """
        Extracts mod, exponent from parsed
        :param ret: 
        :param parsed: 
        :return: 
        """
        try:
            mod16 = base64.b16encode(base64.b64decode(parsed['subject_key_info']['rsa_public_key']['modulus']))
            ret['n'] = '0x%s' % mod16
            ret['e'] = hex(int(parsed['subject_key_info']['rsa_public_key']['exponent']))
            if self.fmagic:
                ret['sec'] = self.fmagic.test16(mod16)
        except Exception as e:
            pass

    def fill_cn_src(self, ret, parsed):
        """
        Fillts in CN, Source
        :param ret: 
        :param parsed: 
        :return: 
        """
        ret['cn'] = utils.defvalkeys(parsed, ['subject', 'common_name', 0])
        not_before = parsed['validity']['start']
        not_before = not_before[:not_before.find('T')]
        ret['source'] = [ret['cn'], not_before]

    def process_record(self, idx, record):
        """
        Current record
        {"e":"0x10001","count":1,"source":["COMMON_NAME","NOT_BEFORE_2010-11-19"],
        "id":32000000,"cn":"COMMON_NAME","n":"0x...","timestamp":1475342704760}

        :param idx: 
        :param record: 
        :return: 
        """
        record['id'] = self.ctr

        ip = utils.defvalkey(record, 'ip')
        domain = utils.defvalkey(record, 'domain')
        timestamp_fmt = utils.defvalkey(record, 'timestamp')
        self.last_record_seen = record

        if not self.is_record_tls(record):
            self.not_tls += 1
            return

        server_cert = record['data']['tls']['server_certificates']
        if 'validation' not in server_cert or 'certificate' not in server_cert:
            self.not_cert_ok += 1
            return

        # Process chains anyway as we may be interested in them even though the server is not RSA
        chains_roots = self.process_roots(idx, record, server_cert)

        # Process server cert
        trusted = utils.defvalkey(server_cert['validation'], 'browser_trusted')
        matches = utils.defvalkey(server_cert['validation'], 'matches_domain')
        cert_obj = server_cert['certificate']

        if 'parsed' not in cert_obj:
            self.not_parsed += 1
            return

        parsed = cert_obj['parsed']
        try:
            ret = collections.OrderedDict()
            if parsed['subject_key_info']['key_algorithm']['name'].lower() != 'rsa':
                self.not_rsa += 1
                return

            ret['id'] = self.ctr
            ret['ip'] = ip
            ret['count'] = 1
            ret['fprint'] = utils.defvalkey(parsed, 'fingerprint_sha256')
            ret['fprint1'] = utils.defvalkey(parsed, 'fingerprint_sha1')
            utils.set_nonempty(ret, 'dom', domain)

            tstamp = utils.try_parse_timestamp(timestamp_fmt)
            ret['timestamp'] = utils.unix_time(tstamp)
            utils.set_nonempty(ret, 'trust', trusted)
            utils.set_nonempty(ret, 'match', matches)
            utils.set_nonempty(ret, 'valid', utils.defvalkeys(parsed, ['signature', 'valid']))
            utils.set_nonempty(ret, 'ssign', utils.defvalkeys(parsed, ['signature', 'self_signed']))

            self.fill_cn_src(ret, parsed)
            self.fill_rsa_ne(ret, parsed)
            ret['chains'] = chains_roots
            self.last_record_flushed = record

            if not self.is_dry():
                self.file_leafs_fh.write(json.dumps(ret) + '\n')

        except Exception as e:
            logger.warning('Certificate processing error %s : %s' % (self.ctr, e))
            logger.debug(traceback.format_exc())
            self.not_cert_ok += 1

    def process_roots(self, idx, record, server_cert):
        """
        Process root certificates
        :param idx: 
        :param record: 
        :param server_cert: 
        :return: 
        """
        chains_ctr = []
        try:
            if 'chain' not in server_cert:
                return chains_ctr

            for cert in server_cert['chain']:
                self.chain_ctr += 1
                if 'parsed' not in cert:
                    continue

                parsed = cert['parsed']
                fprint = parsed['fingerprint_sha256']
                if fprint in self.chain_cert_db:
                    chains_ctr.append(self.chain_cert_db[fprint])
                    continue

                ret = collections.OrderedDict()
                is_rsa = parsed['subject_key_info']['key_algorithm']['name'].lower() == 'rsa'
                if not is_rsa:
                    self.not_rsa += 1

                ret['id'] = self.chain_ctr
                ret['count'] = 1
                ret['chain'] = 1
                ret['valid'] = utils.defvalkeys(parsed, ['signature', 'valid'])
                ret['ssign'] = utils.defvalkeys(parsed, ['signature', 'self_signed'])
                ret['fprint'] = fprint
                ret['fprint1'] = utils.defvalkey(parsed, 'fingerprint_sha1')
                self.fill_cn_src(ret, parsed)
                if is_rsa:
                    self.fill_rsa_ne(ret, parsed)
                ret['raw'] = cert['raw']

                if not self.is_dry():
                    self.file_roots_fh.write(json.dumps(ret) + '\n')

                self.chain_cert_db[fprint] = self.chain_ctr
                chains_ctr.append(self.chain_ctr)

        except Exception as e:
            logger.warning('Chain processing error %s : %s' % (self.chain_ctr, e))
            logger.debug(traceback.format_exc())
            self.not_chain_ok += 1

        return chains_ctr

    def _build_link_object(self, url, rec):
        """
        Builds a link object to be processed
        :param url: 
        :param rec: 
        :return: 
        """
        return input_obj.ReconnectingLinkInputObject(url=url, rec=rec, timeout=5*60, max_reconnects=1000)

    def generate_workset(self):
        """
        Prepares input objects for processing
        :return: 
        """
        # Build input objects
        for file_name in self.args.file:
            iobj = input_obj.FileInputObject(file_name, rec=None)
            self.input_objects.append(iobj)

        for url in self.args.url:
            iobj = self._build_link_object(url=url, rec=None)
            self.input_objects.append(iobj)

        link_indices = None
        if len(self.args.link_idx) > 0:
            link_indices = set([int(x) for x in self.args.link_idx])

        for link_file in self.args.link_file:
            with open(link_file, 'r') as fh:
                data = fh.read()
                js = json.loads(data)
                datasets = js['data']

            for dataset in datasets:
                did = dataset['id']
                if link_indices is not None and did not in link_indices:
                    continue

                iobj = self._build_link_object(url=dataset['files']['zgrab-results.json.lz4']['href'], rec=dataset)
                self.input_objects.append(iobj)

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        self.generate_workset()

        # Process all input objects
        if self.args.mpi:
            self.process_mpi()
        else:
            self.process()

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Censys TLS dataset processor')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--scratch', dest='scratch_dir', default='.',
                            help='Scratch directory output')

        parser.add_argument('-t', dest='threads', default=1,
                            help='Number of download threads to use')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--dry-run', dest='dry_run', default=False, action='store_const', const=True,
                            help='Dry run - no file will be overwritten or deleted')

        parser.add_argument('--continue', dest='continue1', default=False, action='store_const', const=True,
                            help='Continue from the previous attempt')

        parser.add_argument('--continue-frac', dest='continue_frac', default=None, type=float,
                            help='Fraction of the file to start reading from')

        parser.add_argument('--link-file', dest='link_file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='JSON file generated by censys_links.py')

        parser.add_argument('--link-idx', dest='link_idx', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Link indices to process')

        parser.add_argument('--file', dest='file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 files to process')

        parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 URL to process')

        parser.add_argument('--mpi', dest='mpi', default=False, action='store_const', const=True,
                            help='Use MPI distribution')

        parser.add_argument('--sec', dest='sec', default=False, action='store_const', const=True,
                            help='Use sec')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        if self.args.sec:
            import sec
            self.fmagic = sec.Fprinter()

        self.work()


def main():
   app = CensysTls()
   app.main()


if __name__ == '__main__':
    main()


