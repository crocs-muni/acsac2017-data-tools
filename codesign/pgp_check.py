#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Check PGP keys & subkeys
"""

import re
import os
import math
import json
import argparse
import logging
import coloredlogs
import traceback
import time
import datetime
import utils
import versions as vv
import databaseutils
from collections import OrderedDict, defaultdict
import sec


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class PGPCheck(object):
    """
    PGP keys checking - processes PGP json with already parsed keys.
    """

    def __init__(self):
        self.args = None
        self.fmagic = None

        self.config = None
        self.config_file = None
        self.dump_file = None
        self.classif_file = None

        self.last_report = 0
        self.last_report_idx = 0
        self.last_flush = 0
        self.report_time = 15

        self.found = 0
        self.found_master_key = 0
        self.found_no_master_key = 0
        self.found_sub_key = 0
        self.found_entities = 0
        self.found_entities_keynum = 0
        self.found_master_not_rsa = 0
        self.found_key_counts = defaultdict(lambda: 0)
        self.found_key_sizes = defaultdict(lambda: 0)
        self.found_info = []

        self.num_master_keys = 0
        self.num_sub_keys = 0
        self.num_master_keys_rsa = 0
        self.num_sub_keys_rsa = 0

        self.num_total_keys_date = 0
        self.num_total_master_keys_date = 0
        self.num_rsa_keys_date = 0
        self.num_rsa_master_keys_date = 0

        self.key_counts = defaultdict(lambda: 0)
        self.key_sizes = defaultdict(lambda: 0)

        self.bench_mods = []

        self.no_key_id = 0
        self.flat_key_ids = set()

    def work(self):
        """
        Entry working point
        :return: 
        """
        logger.info('Starting...')
        dump_file_path = os.path.join(self.args.data_dir, 'pgp_inter_keys.json')
        self.dump_file = open(dump_file_path, 'w')

        if self.args.classif:
            classif_path = os.path.join(self.args.data_dir, 'pgp_classif_full.json')
            self.classif_file = open(classif_path, 'w')

        # process PGP dump, fill in keys DB
        with open(self.args.json) as fh:
            for idx, line in enumerate(fh):
                try:
                    self.process_record(idx, line)

                    if self.args.test and self.num_master_keys > 10000:
                        break

                except Exception as e:
                    logger.error('Exception when processing line %s: %s' % (idx, e))
                    logger.debug(traceback.format_exc())

        self.dump_file.close()

        # fprint keys
        logger.info('Job finished')
        logger.info('Found: %s' % self.found)
        logger.info('Found unique: %s' % len(self.flat_key_ids))
        logger.info('Found entities: %s' % self.found_entities)
        logger.info('Found master: %s' % self.found_master_key)
        logger.info('Found no master: %s' % self.found_no_master_key)
        logger.info('Found sub key: %s' % self.found_sub_key)
        logger.info('Found avg num of keys: %s' % ((float(self.found_entities_keynum) / self.found_entities)
                    if self.found_entities > 0 else -1))
        logger.info('Found master not RSA: %s' % self.found_master_not_rsa)
        logger.info('Num master keys: %s' % self.num_master_keys)
        logger.info('Num sub keys: %s' % self.num_sub_keys)
        logger.info('Num master RSA keys: %s' % self.num_master_keys_rsa)
        logger.info('Num sub RSA keys: %s' % self.num_sub_keys_rsa)

        logger.info('1.11.2015 - 19.4.2017 total keys: %s' % self.num_total_keys_date)
        logger.info('1.11.2015 - 19.4.2017 master keys: %s' % self.num_total_master_keys_date)
        logger.info('1.11.2015 - 19.4.2017 RSA total keys: %s' % self.num_rsa_keys_date)
        logger.info('1.11.2015 - 19.4.2017 RSA master keys: %s' % self.num_rsa_master_keys_date)

        total_rsa = self.num_master_keys_rsa + self.num_sub_keys_rsa
        logger.info('Key count histogram')
        for cnt in sorted(self.key_counts.keys()):
            logger.info('  .. Key count %8d: %8d (%8.6f)'
                        % (cnt, self.key_counts[cnt], float(self.key_counts[cnt]) / self.num_master_keys))

        logger.info('RSA Key size histogram')
        for cnt in sorted(self.key_sizes.keys()):
            logger.info('  .. Key count %8s: %8d (%8.6f)'
                        % (cnt, self.key_sizes[cnt], float(self.key_sizes[cnt]) / total_rsa))

        logger.info('Found Key count histogram')
        for cnt in sorted(self.found_key_counts.keys()):
            logger.info('  .. size count %8d: %8d (%8.6f)'
                        % (cnt, self.found_key_counts[cnt], (float(self.found_key_counts[cnt]) / self.found_entities)
            if self.found_entities > 0 else -1))

        logger.info('Found RSA Key sizes histogram')
        for cnt in sorted(self.found_key_sizes.keys()):
            logger.info('  .. size count %8s: %8d (%8.6f)'
                        % (cnt, self.found_key_sizes[cnt], (float(self.found_key_sizes[cnt]) / self.found)
            if self.found > 0 else -1))

        logger.info('Found records data:')
        records_path = os.path.join(self.args.data_dir, 'pgp_inter_keys.csv')
        with open(records_path, 'w') as fw:
            for x in self.found_info:
                try:
                    fw.write((';'.join([str(y) for y in x])) + '\n')
                except Exception as e:
                    logger.error('Exception in dump, %s' % e)
                    logger.debug(traceback.format_exc())

        keys_path = os.path.join(self.args.data_dir, 'pgp_inter_keys_ids.csv')
        with open(keys_path, 'w') as fw:
            for x in sorted(list(self.flat_key_ids)):
                fw.write(utils.format_pgp_key(x) + '\n')

        if self.classif_file is not None:
            self.classif_file.close()

        if self.args.bench:
            logger.info('Benchmark start, total keys: %s' % len(self.bench_mods))
            stime = time.time()
            fd = 0
            for x in self.bench_mods:
                y = self.fmagic.magic16([x])
                if len(y) > 0:
                    fd += 1

            bech_total = time.time() - stime
            logger.info('Benchmark finished, found: %s, total: %s' % (fd, bech_total))

    def process_record(self, idx, line):
        """
        Processes one record from PGP dump
        :param idx: 
        :param line: 
        :return: 
        """
        rec = json.loads(line)
        master_key_id = int(utils.defvalkey(rec, 'key_id', '0'), 16)
        master_fingerprint = utils.defvalkey(rec, 'fingerprint')

        flat_keys = [rec]
        user_names = []

        # Phase 1 - info extraction
        if 'packets' in rec:
            for packet in rec['packets']:
                if packet['tag_name'] == 'User ID':
                    utils.append_not_none(user_names, utils.defvalkey(packet, 'user_id'))
                elif packet['tag_name'] == 'Public-Subkey':
                    flat_keys.append(packet)

        # Test all keys
        self.test_flat_keys(flat_keys, user_names, master_key_id, master_fingerprint, rec)

        if time.time() - self.last_report > self.report_time:
            per_second = (idx - self.last_report_idx) / float(self.report_time)
            logger.debug(' .. report idx: %s, per second: %2.2f, found: %s, '
                         'num_master: %s, num_sub: %s, ratio: %s, cur key: %016X '
                         % (idx, per_second, self.found, self.num_master_keys, self.num_sub_keys,
                            float(self.num_sub_keys) / self.num_master_keys, master_key_id))

            self.last_report = time.time()
            self.last_report_idx = idx

    def test_flat_keys(self, flat_keys, user_names, master_key_id, master_fingerprint, rec):
        """
        Tests all keys in the array
        :param flat_keys: 
        :return: 
        """
        if flat_keys is None or len(flat_keys) == 0:
            return

        self.num_master_keys += 1
        self.num_sub_keys += len(flat_keys) - 1

        rsa_keys = ['n' in x and len(x['n']) > 0 for x in flat_keys]
        self.num_master_keys_rsa += rsa_keys[0]
        self.num_sub_keys_rsa += sum(rsa_keys[1:])
        self.key_counts[len(flat_keys)] += 1

        key_sizes = [self.key_size(x) for x in flat_keys]
        for x in key_sizes:
            self.key_sizes[x] += 1

        # benchmarking
        if self.args.bench:
            for rec in flat_keys:
                n = self.key_mod(rec)
                if n is None or n == 0:
                    continue

                self.bench_mods.append('%x' % n)

        # 1.11.2015 a 19.4.2017
        bnd_a = datetime.datetime(year=2015, month=11, day=1)
        bnd_b = datetime.datetime(year=2017, month=4, day=19, hour=23, minute=59, second=59)
        in_time = ['creation_time' in rec and
                   utils.time_between(datetime.datetime.utcfromtimestamp(rec['creation_time']), bnd_a, bnd_b)
                   for rec in flat_keys]
        rsa_in_time = ['n' in rec and len(rec['n']) > 0 and in_time[idx] for idx, rec in enumerate(flat_keys)]

        self.num_total_keys_date += sum(in_time)
        self.num_total_master_keys_date += in_time[0]
        self.num_rsa_keys_date += sum(rsa_in_time)
        self.num_rsa_master_keys_date += rsa_in_time[0]

        # key testing
        tested = [self.test_key(x) for x in flat_keys]

        # classification
        if self.classif_file is not None:
            for idx, rec in enumerate(flat_keys):
                if 'n' not in rec:
                    continue

                js = OrderedDict()
                ctime = datetime.datetime.utcfromtimestamp(rec['creation_time']).strftime('%Y-%m-%d') \
                    if 'creation_time' in rec else ''
                cname = user_names[0].encode('utf8').replace(';', '_') if len(user_names) > 0 else ''

                js['source'] = [cname, ctime]
                js['size'] = self.key_size(rec)
                js['msb'] = '0x%x' % self.key_msb(rec)
                js['sub'] = int(idx != 0)
                js['master_id'] = utils.format_pgp_key(master_key_id)
                js['sec'] = int(tested[idx])
                js['tot'] = len(flat_keys)
                js['e'] = '0x%x' % self.key_exp(rec)
                js['n'] = '0x%x' % self.key_mod(rec)
                self.classif_file.write('%s\n' % json.dumps(js))

        # Key detection and store
        if any(tested):
            flat_key_ids = [int(utils.defvalkey(x, 'key_id', '0'), 16) for x in flat_keys]
            keys_hex = [utils.format_pgp_key(x) for x in flat_key_ids]
            det_key_ids = [x for _idx, x in enumerate(flat_key_ids) if tested[_idx]]

            logger.info('------- interesting map: %s for key ids %s' % (tested, keys_hex))

            js = OrderedDict()
            js['detection'] = tested
            js['key_ids'] = keys_hex
            js['names'] = user_names
            js['master_key_id'] = utils.format_pgp_key(master_key_id)
            js['master_key_fprint'] = master_fingerprint
            # js['pgp'] = rec

            self.dump_file.write(json.dumps(js) + '\n')
            self.dump_file.flush()

            self.found_no_master_key += not tested[0]
            self.found_master_key += tested[0]
            self.found_sub_key += sum(tested[1:])
            self.found += sum(tested)
            self.found_entities += 1
            self.found_entities_keynum += len(tested)
            self.found_master_not_rsa += not rsa_keys[0]
            self.found_key_counts[len(flat_keys)] += 1
            for x in det_key_ids:
                self.flat_key_ids.add(x)

            for idx, x in enumerate(key_sizes):
                if tested[idx]:
                    self.found_key_sizes[x] += 1

            for idx, x in enumerate(tested):
                if not tested[idx]:
                    continue

                # 2012-04-30; rsa_bit_length; subkey_yes_no; email; MSB(modulus); modulus;
                rec = flat_keys[idx]

                res = []
                res.append(datetime.datetime.utcfromtimestamp(rec['creation_time']).strftime('%Y-%m-%d') if 'creation_time' in rec else '')
                res.append(self.key_size(rec))
                res.append(int(idx == 0))
                res.append(user_names[0].encode('utf8').replace(';', '_') if len(user_names) > 0 else '')
                res.append('%x' % self.key_msb(rec))
                res.append('%x' % self.key_mod(rec))
                self.found_info.append(res)

    def test_key(self, rec=None):
        """
        Fingerprint test
        :param rec: 
        :return: 
        """
        if rec is None:
            return False

        n = utils.defvalkey(rec, 'n')
        if n is None:
            return False

        n = n.strip()
        n = utils.strip_hex_prefix(n)

        x = self.fmagic.magic16([n])
        if len(x) > 0:
            return True
        return False

    def key_mod(self, rec=None):
        """
        Returns modulus from the record
        :param rec: 
        :return: 
        """
        if rec is None:
            return False

        n = utils.defvalkey(rec, 'n')
        if n is None:
            return False

        n = n.strip()
        n = utils.strip_hex_prefix(n)
        return int(n, 16)

    def key_exp(self, rec=None):
        """
        Returns exponent from the record
        :param rec: 
        :return: 
        """
        if rec is None:
            return False

        n = utils.defvalkey(rec, 'e')
        if n is None:
            return False

        n = n.strip()
        n = utils.strip_hex_prefix(n)
        return int(n, 16)

    def key_size(self, rec=None, n=None):
        """
        Get key size from the modulus
        :param rec: 
        :param n: 
        :return: 
        """
        if n is None:
            n = self.key_mod(rec)
        if n is None or n == 0:
            return None
        return int(math.ceil(math.log(n, 2)))

    def key_msb(self, rec=None):
        """
        Returns the MSB
        :param rec: 
        :return: 
        """
        n = self.key_mod(rec)
        if n is None:
            return None
        size = self.key_size(n=n)
        if size == 0:
            return None
        return 0 if n == 0 else (n >> (((size - 1) >> 3) << 3))

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='PGP dump analyser')

        parser.add_argument('-c', dest='config', default=None,
                            help='JSON config file')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--bench', dest='bench', default=False, action='store_const', const=True,
                            help='Benchmark ')

        parser.add_argument('--test', dest='test', default=False, action='store_const', const=True,
                            help='Test ')

        parser.add_argument('--classif', dest='classif', default=False, action='store_const', const=True,
                            help='Generate classification JSON with all records')

        parser.add_argument('--json', dest='json', default=None,
                            help='Big json file from pgp dump')

        self.args = parser.parse_args()
        self.config_file = self.args.config

        self.fmagic = sec.Fprinter()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
    app = PGPCheck()
    app.main()


if __name__ == '__main__':
    main()

