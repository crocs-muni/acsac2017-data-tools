#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PGP key classification
"""

import json
import argparse
import logging
import coloredlogs
import types
import base64
import sys
import os
import tarfile
import utils
import collections
from trace_logger import Tracelogger

from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class PgpClassification(object):
    """
    PGP key classification - parses ASCII armored PGP keys
    """

    def __init__(self):
        self.args = None
        self.fmagic = None
        self.tested = 0
        self.found = 0

        self.trace_logger = Tracelogger(logger)
        self.fh = None

    def strtime(self, x):
        """
        Simple time format
        :param x: 
        :return: 
        """
        if x is None:
            return x
        return x.strftime('%Y-%m-%d')

    def process_key(self, data, fname):
        """
        Processes single PGP key
        :param data: file data
        :param fname: file name
        :return: 
        """
        try:
            self.process_key_raw(data, fname)

        except Exception as e:
            logger.error('Exception in processing file %s: %s' % (fname, e))
            self.trace_logger.log(e)

    def process_key_raw(self, data, fname):
        """
        Processes single PGP key
        :param data: file data
        :param fname: file name
        :return: 
        """
        js = collections.OrderedDict()

        pgp_key_data = AsciiData(data)
        packets = list(pgp_key_data.packets())

        creation_time = None
        master_fprint = None
        master_key_id = None
        identities = []
        pubkeys = []
        sig_cnt = 0
        for idx, packet in enumerate(packets):
            if isinstance(packet, PublicKeyPacket):
                master_fprint = packet.fingerprint
                master_key_id = utils.format_pgp_key(packet.key_id)
                creation_time = self.strtime(packet.creation_time)
                pubkeys.append(packet)
            elif isinstance(packet, PublicSubkeyPacket):
                pubkeys.append(packet)
            elif isinstance(packet, UserIDPacket):
                identities.append(packet)
            elif isinstance(packet, SignaturePacket):
                sig_cnt += 1

        # Names / identities
        ids_arr = []
        identity = None
        for packet in identities:
            idjs = collections.OrderedDict()
            idjs['name'] = packet.user_name
            idjs['email'] = packet.user_email
            ids_arr.append(idjs)

            if identity is None:
                identity = '%s <%s>' % (packet.user_name, packet.user_email)

        js['source'] = [identity, creation_time]
        js['identities'] = ids_arr
        js['signatures_count'] = sig_cnt
        js['packets_count'] = len(packets)
        js['keys_count'] = len(pubkeys)

        # Public keys processing
        for packet in pubkeys:
            try:
                jsc = collections.OrderedDict(js)
                is_master = master_fprint == packet.fingerprint

                jsc['source'] = [identity, self.strtime(packet.creation_time)]
                jsc['fprint'] = utils.lower(packet.fingerprint)
                jsc['kid'] = utils.format_pgp_key(packet.key_id)
                jsc['is_master'] = is_master
                if is_master:
                    jsc['master_fprint'] = None
                    jsc['master_kid'] = None
                else:
                    jsc['master_fprint'] = utils.lower(master_fprint)
                    jsc['master_kid'] = master_key_id

                jsc['pk_ver'] = packet.pubkey_version
                if packet.modulus is None:
                    continue

                jsc['e'] = '0x%x' % packet.exponent
                jsc['nsize'] = packet.modulus_bitlen
                jsc['n'] = '0x%x' % packet.modulus

                jsc['created_at'] = self.strtime(packet.creation_time)
                jsc['expires_at'] = self.strtime(packet.expiration_time)
                jsc['sec'] = self.test_mod(packet.modulus, jsc['kid'])
                self.fh.write('%s\n' % json.dumps(jsc))
            except Exception as e:
                logger.error('Excetion in processing the key: %s' % e)
                self.trace_logger.log(e)

    def test_mod(self, n, key_id=None):
        """
        Mod testing - fprint
        :param n: 
        :return: 
        """
        if n is None:
            return False
        if self.fmagic is None:
            return False
        if isinstance(n, (types.IntType, types.LongType)):
            n = '%x' % n

        n = n.strip()
        n = utils.strip_hex_prefix(n)

        if self.fmagic.test16(n):
            self.found += 1
            if key_id is not None:
                logger.info('---------------!!!-------------- Keyid: %s' % key_id)
            return True
        return False

    def process_tar(self, fname):
        """
        Tar(gz) archive processing
        :param fname: 
        :return: 
        """
        with tarfile.open(fname) as tr:
            members = tr.getmembers()
            for member in members:
                if not member.isfile():
                    continue
                fh = tr.extractfile(member)
                self.process_key(fh.read(), member.name)

    def process_dir(self, dirname):
        """
        Directory processing
        :param dirname: 
        :return: 
        """
        onlyfiles = [f for f in os.listdir(dirname) if os.path.isfile(os.path.join(dirname, f))]
        for fname in onlyfiles:
            with open(fname) as fh:
                self.process_key(fh.read(), fname)

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """

        if not os.path.exists(self.args.data_dir):
            utils.make_or_verify_dir(self.args.data_dir)

        keys_data = []
        classif_file = os.path.join(self.args.data_dir, 'pgp_classification.json')
        self.fh = open(classif_file, 'w')

        files = self.args.files
        for fname in files:
            if fname == '-':
                fh = sys.stdin
            elif fname.endswith('.tar') or fname.endswith('.tar.gz'):
                self.process_tar(fname)
                continue
            elif not os.path.isfile(fname):
                self.process_dir(fname)
                continue
            else:
                fh = open(fname, 'r')

            with fh:
                data = fh.read()
                self.process_key(data, fname)

        logger.info('Records tested: %s, found: %s' % (self.tested, self.found))
        if self.args.dump_keys:
            for x in keys_data:
                print('%s;%s' % (x[0], self.hex_if_num(x[1])))

        self.fh.close()

    def hex_if_num(self, x):
        """
        returns hex string if modulus is not none
        :param x: 
        :return: 
        """
        if x is None:
            return None
        if isinstance(x, (types.IntType, types.LongType)):
            return '%x' % x
        else:
            return str(x)

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='PGP classification')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--sec', dest='sec', default=False, action='store_const', const=True,
                            help='Sec')

        parser.add_argument('--dump-keys', dest='dump_keys', default=False, action='store_const', const=True,
                            help='dump keys')

        parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='files / folders to process')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        if self.args.sec:
            import sec
            self.fmagic = sec.Fprinter()

        self.work()


def main():
    app = PgpClassification()
    app.main()


if __name__ == '__main__':
    main()

