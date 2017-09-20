#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import argparse
import logging
import coloredlogs
import input_obj
import collections
import base64
import traceback
import time
import os
import json
import utils
import lz4framed
import newline_reader

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


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


class Lz4MetadataGenerator(object):
    """
    Reads LZ4 file, generates checkpoints
    """
    def __init__(self):
        self.args = None

        self.ctr = 0
        self.read_data = 0
        self.last_report = 0

        self.cur_copy_fh = None
        self.cur_state_file = None
        self.cur_decompressor = None
        self.decompressor_checkpoints = collections.OrderedDict()
        self.processor = None
        self.loaded_checkpoint = None

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

    def try_store_checkpoint(self, iobj, idx=None):
        """
        Try-catch store checkpoint to handle situations when files cannot be flushed.
        In that case checkpoint cannot be stored, otherwise we won't be able to restore it properly.
        :param iobj: 
        :param idx: 
        :return: 
        """
        attempts = 0
        while True:
            try:
                return self.store_checkpoint(iobj, idx)

            except Exception as e:
                logger.error('Exception in storing a checkpoint %d: %s' % (attempts, e))
                logger.debug(traceback.format_exc())
                attempts += 1
                time.sleep(15)

    def store_checkpoint(self, iobj, idx=None):
        """
        Stores checkpoint for the current input object
        :param iobj: 
        :param idx: 
        :return: 
        """
        state_file = self.cur_state_file
        input_name = self.iobj_name(iobj)

        # Most importantly, flush data file buffers now so the state is in sync with the checkpoint.
        if self.cur_copy_fh is not None:
            self.cur_copy_fh.flush()

        js = collections.OrderedDict()
        js['iobj_name'] = input_name
        js['time'] = time.time()
        js['read_raw'] = self.read_data
        js['read_processor'] = self.processor.total_len
        js['block_idx'] = idx

        # Serialize input object state
        js['iobj'] = iobj.to_state()

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

            if self.cur_decompressor is not None and 'dec_ctx' in js:
                logger.info('Restoring decompressor state')
                decctx_str = base64.b16decode(js['dec_ctx'])
                decctx = lz4framed.unmarshal_decompression_context(decctx_str)
                self.cur_decompressor.setctx(decctx)
                self.loaded_checkpoint['dec_ctx'] = None

        logger.info('Decompressor checkpoint restored for %s' % input_name)

    def process(self, iobj):
        """
        Process input object - read LZ4, produce metadata
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
        self.processor = newline_reader.NewlineReader(is_json=False)
        if self.args.copy_dir is not None:
            copy_path = os.path.join(self.args.copy_dir, input_name)
            logger.info('Going to create a copy to %s' % copy_path)
            self.cur_copy_fh = open(copy_path, 'w')

        handle = iobj
        name = str(iobj)

        if self.cur_copy_fh is not None:
            handle = input_obj.TeeInputObject(parent_fh=handle, copy_fh=self.cur_copy_fh)

        if name.endswith('lz4'):
            self.cur_decompressor = lz4framed.Decompressor(handle)
            handle = self.cur_decompressor

        if self.args.continue1:
            logger.info('Continuing with the started files')
            self.restore_checkpoint(iobj)

        with iobj:
            record_ctr = -1
            read_start = self.read_data
            for idx, record in self.processor.process(handle):
                try:
                    record_ctr += 1
                    self.read_data += len(record)

                    # Check the checkpoint distance + boundary - process all newline chunks available
                    if self.read_data - self.last_report >= 1024 * 1024 * 1024 and self.processor.step_cur_last_element:

                        logger.info('...progress: %s GB, idx: %s, pos: %s GB, mem: %04.8f MB, readpos: %s (%4.6f GB)'
                                    % (self.read_data / 1024.0 / 1024.0 / 1024.0, idx, self.read_data,
                                       utils.get_mem_usage() / 1024.0, iobj.tell(),
                                       iobj.tell() / 1024.0 / 1024.0 / 1024.0))

                        self.last_report = self.read_data
                        self.try_store_checkpoint(iobj=iobj, idx=idx)

                        # Flush already seen IP database, not needed anymore
                        # we are too far from the resumed checkpoint
                        if read_start + 1024 * 1024 * 1024 * 2 > self.read_data:
                            self.state_loaded_ips = set()

                except Exception as e:
                    logger.error('Exception in processing %d: %s' % (self.ctr, e))
                    logger.debug(traceback.format_exc())

                self.ctr += 1

        logger.info('Processed: %s' % iobj)

        if self.cur_copy_fh is not None:
            self.cur_copy_fh.close()
        utils.try_touch(finish_file)

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        iobjs = []

        for url in self.args.url:
            iobjs.append(input_obj.ReconnectingLinkInputObject(url=url))

        for file in self.args.file:
            iobjs.append(input_obj.FileInputObject(file))

        for iobj in iobjs:
            self.process(iobj)

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='LZ4 metadata generator for random access')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--scratch', dest='scratch_dir', default='.',
                            help='Scratch directory output')

        parser.add_argument('--copy', dest='copy_dir', default=None,
                            help='Directory to copy the read data')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--dry-run', dest='dry_run', default=False, action='store_const', const=True,
                            help='Dry run - no file will be overwritten or deleted')

        parser.add_argument('--continue', dest='continue1', default=False, action='store_const', const=True,
                            help='Continue from the previous attempt')

        parser.add_argument('--file', dest='file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 files to process')

        parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 URL to process')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
   app = Lz4MetadataGenerator()
   app.main()


if __name__ == '__main__':
    main()



