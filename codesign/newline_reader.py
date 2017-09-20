#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import json
import traceback
import hashlib
import string


logger = logging.getLogger(__name__)


class NewlineIterator(object):
    """
    Wraps any object with read() method so it returns line by line on iterating.
    """

    def __init__(self, fh):
        self._fh = fh
        self._data = ''
        self._offset = 0  # position in unzipped stream
        self._done = False

    def __fill(self, num_bytes):
        """
        Fill the internal buffer with 'num_bytes' of data.
        @param num_bytes: int, number of bytes to read in (0 = everything)
        """
        if self._done:
            return

        while not num_bytes or len(self._data) < num_bytes:
            data = self._fh.read(32768)
            if not data:
                self._done = True
                break

            self._data = self._data + data

    def __iter__(self):
        return self

    def next(self):
        line = self.readline()
        if not line:
            raise StopIteration()
        return line

    def read(self, size=0):
        self.__fill(size)
        if size:
            data = self._data[:size]
            self._data = self._data[size:]
        else:
            data = self._data
            self._data = ""
        self._offset = self._offset + len(data)
        return data

    def readline(self):
        # make sure we have an entire line
        while not self._done and "\n" not in self._data:
            self.__fill(len(self._data) + 512)

        pos = string.find(self._data, "\n") + 1
        if pos <= 0:
            return self.read()
        return self.read(pos)

    def readlines(self):
        lines = []
        while True:
            line = self.readline()
            if not line:
                break
            lines.append(line)
        return lines


class ContextNewlineIterator(NewlineIterator):
    """
    Same as NewlineIterator but supports context manager with enter / exit on the fh
    """
    def __init__(self, fh):
        super(ContextNewlineIterator, self).__init__(fh)

    def __enter__(self):
        self._fh.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._fh.__exit__(exc_type, exc_val, exc_tb)


class NewlineReader(object):
    """
    Very simple newline separated JSON reader.
    Optimized for use with lz4 decompressor.
    """
    def __init__(self, is_json=True, *args, **kwargs):
        self.is_json = is_json

        # State of the processing
        self.digest = None
        self.digest_final_hex = None

        self.total_len = 0
        self.ctr = 0
        self.chunk_idx = 0
        self.buffer = ''

        # Control / callbacks
        self.abort = False
        self.on_chunk_process = None
        self.on_record_process = None

        # Current state
        self.step_elements = 0
        self.step_cur_element = 0
        self.step_cur_last_element = 0

    def process(self, file_like):
        """
        Processes file like object in a streamed manner.
        :param file_like: 
        :return: 
        """
        self.total_len = 0
        self.digest = hashlib.sha256()

        for idx, chunk in enumerate(file_like):
            self.chunk_idx = idx
            self.total_len += len(chunk)
            self.digest.update(chunk)

            # Loading all elements in one batch from the buffer, for processing caller may need the length.
            elements = [x for x in self.process_chunk(self.chunk_idx, chunk)]
            self.step_elements = len(elements)
            for eidx, x in enumerate(elements):
                self.step_cur_element = eidx
                self.step_cur_last_element = eidx+1 == self.step_elements
                yield x

            if self.abort:
                logger.info('Abort set, terminating')
                return

        # Finish the buffer completely
        self.chunk_idx += 1
        for x in self.process_chunk(self.chunk_idx, '', True):
            yield x

        self.digest_final_hex = self.digest.hexdigest()
        logger.info('Processing finished, total length: %s, hash: %s' % (self.total_len, self.digest_final_hex))

    def process_chunk(self, idx, chunk, finalize=False):
        """
        Process one chunk of decrypted data. Length is arbitrary. We have to watch out the underlying format.
        :param idx: chunk index
        :param chunk: data chunk to process
        :param finalize: if true no more data is going to be loaded, read all what you can 
        :return: 
        """
        self.buffer += chunk

        if self.on_chunk_process is not None:
            self.on_chunk_process(idx, chunk)

        while True:
            pos = self.buffer.find('\n')
            if pos < 0:
                # Check the size of the buffer, log if buffer is too long. Can signalize something broke
                ln = len(self.buffer)
                if ln > 100000:
                    logger.info('Chunk %d without newline, len: %d' % (idx, ln))

                # Wait for next chunk
                if not finalize or ln == 0:
                    return
                else:
                    pos = ln

            part = (self.buffer[0:pos]).strip()
            self.buffer = (self.buffer[pos+1:])

            self.ctr += 1
            try:
                obj = json.loads(part) if self.is_json else part
                yield idx, obj

            except Exception as e:
                logger.error('Exception when parsing pos %d, part: %s' % (self.ctr, e))
                logger.info(traceback.format_exc())
                logger.info(part)





