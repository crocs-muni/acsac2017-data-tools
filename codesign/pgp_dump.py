#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key fingerprinting
"""

import json
import argparse
import logging
import coloredlogs
import types
import base64
import sys

from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class PgpDump(object):
    """
    PGP dump - reads ASCII armored PGP key, dumps info on stdout
    """

    def __init__(self):
        self.args = None
        self.fmagic = None
        self.tested = 0
        self.found = 0

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        if self.args.sec:
            import sec
            self.fmagic = sec.Fprinter()

        keys_data = []

        files = self.args.files
        for fname in files:
            if fname == '-':
                fh = sys.stdin
            else:
                fh = open(fname, 'r')

            with fh:
                key = fh.read()
                pgp_key_data = AsciiData(key)
                packets = list(pgp_key_data.packets())
                print('File: %s' % fname)
                print('Packets: %s' % len(packets))
                print('-' * 80)

                identities = []
                pubkeys = []
                for idx, packet in enumerate(packets):
                    if isinstance(packet, (PublicKeyPacket, PublicSubkeyPacket)):
                        pubkeys.append(packet)
                    elif isinstance(packet, UserIDPacket):
                        identities.append(packet)

                print('Identities: ')
                for packet in identities:
                    print('User: %s' % packet.user)
                    print('User name: %s' % packet.user_name)
                    print('User email: %s' % packet.user_email)
                    print('-' * 80)

                print('Publickeys: ')
                for packet in pubkeys:
                    print('Is subkey: %s' % isinstance(packet, PublicSubkeyPacket))
                    print('Algorithm: %s' % packet.pub_algorithm)
                    print('Pub key version: %s' % packet.pubkey_version)
                    print('Fingerprint: %s' % packet.fingerprint)
                    print('key_id: %s' % packet.key_id)
                    print('creation_time: %s' % packet.creation_time)
                    print('expiration_time: %s' % packet.expiration_time)
                    print('raw_days_valid: %s' % packet.raw_days_valid)
                    print('pub_algorithm_type: %s' % packet.pub_algorithm_type)
                    print('modulus: %s' % self.hex_if_num(packet.modulus))
                    print('modulus_bitlen: %s' % packet.modulus_bitlen)
                    print('exponent: %s' % self.hex_if_num(packet.exponent))
                    print('prime: %s' % self.hex_if_num(packet.prime))
                    print('group_order: %s' % self.hex_if_num(packet.group_order))
                    print('group_gen: %s' % self.hex_if_num(packet.group_gen))
                    print('key_value: %s' % packet.key_value)
                    print('-' * 80)

                    if packet.modulus is not None:
                        keys_data.append((packet.modulus_bitlen, packet.modulus, ))

                    if self.args.sec and packet.modulus is not None:
                        n = '%x' % packet.modulus
                        x = self.fmagic.magic16([n])
                        self.tested += 1
                        if len(x) > 0:
                            self.found += 1
                            print('---- !!! ----')

        logger.info('Records tested: %s, found: %s' % (self.tested, self.found))
        if self.args.dump_keys:
            for x in keys_data:
                print('%s;%s' % (x[0], self.hex_if_num(x[1])))

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
        parser = argparse.ArgumentParser(description='PGP key analysis')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--sec', dest='sec', default=False, action='store_const', const=True,
                            help='Sec')

        parser.add_argument('--dump-keys', dest='dump_keys', default=False, action='store_const', const=True,
                            help='dump keys')

        parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='files to process')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
    app = PgpDump()
    app.main()


if __name__ == '__main__':
    main()

