#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Downloads PGP key based on the key id
"""


import os
import sys
import argparse
import inspect
import logging
import coloredlogs
from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

try:
    from codesign import utils
except:
    import utils


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Downloads PGP key based on the key id')
    parser.add_argument('keyids', nargs=argparse.ZERO_OR_MORE, default=[], help='key id')
    args = parser.parse_args()

    for key_id_txt in args.keyids:
        key_id = utils.strip_hex_prefix(key_id_txt)
        key_id = utils.format_pgp_key(int(key_id, 16))

        key = utils.get_pgp_key(key_id)
        pgp_key_data = AsciiData(key)
        packets = list(pgp_key_data.packets())
        print('Packets: %s' % len(packets))
        print('-' * 80)

        identities = []
        pubkeys = []
        for idx, packet in enumerate(packets):
            if isinstance(packet, (PublicKeyPacket, PublicSubkeyPacket)):  # PublicSubkeyPacket
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
            print('modulus: %s' % packet.modulus)
            print('modulus_bitlen: %s' % packet.modulus_bitlen)
            print('exponent: %s' % packet.exponent)
            print('prime: %s' % packet.prime)
            print('group_order: %s' % packet.group_order)
            print('group_gen: %s' % packet.group_gen)
            print('key_value: %s' % packet.key_value)
            print('-' * 80)


if __name__ == "__main__":
    main()


