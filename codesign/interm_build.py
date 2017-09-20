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
import binascii
import types

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography import x509

from OpenSSL.crypto import load_certificate, load_privatekey, FILETYPE_PEM, FILETYPE_ASN1, X509StoreContextError
from OpenSSL.crypto import X509Store, X509StoreContext
from six import u, b, binary_type, PY3

import base64
import time

import input_obj
import lz4framed
import newline_reader
from trace_logger import Tracelogger

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


FMT_TLS = 1
FMT_SON = 2
FMT_ECO = 3


def get_backend(backend=None):
    return default_backend() if backend is None else backend


class Dataset(object):
    def __init__(self, fname=None, fmt=None):
        self.fname = fname
        self.fmt = fmt


class IntermediateBuilder(object):
    """
    Builds intermediate CA database from existing datasets
    """

    def __init__(self):
        self.args = None
        self.trace_logger = Tracelogger(logger=logger)
        self.chain_cert_db = set()
        self.fmagic = None

        self.ctr = 0
        self.input_objects = []

        self.assigned_fprints = set()
        self.cur_depth = 1
        self.root_store = self.new_store()
        self.cur_store = self.new_store()
        self.all_certs = []
        self.interms = {}

        self.state_last_dump = 0
        self.state_time_dump = 60
        self.cur_file = None

        self.num_no_fprint_raw = 0
        self.num_no_raw = 0
        self.num_not_ca = 0
        self.num_errs = 0
        self.num_non_rsa = 0
        self.num_rsa = 0
        self.num_expired = 0
        self.num_found = 0

    def new_store(self):
        """
        Creates a new store
        # define X509_V_FLAG_NO_CHECK_TIME               0x200000
        :return: 
        """
        store = X509Store()
        store.set_flags(0x200000)
        return store

    def load_roots(self):
        """
        Loads root certificates
        File downloaded from: https://curl.haxx.se/docs/caextract.html
        :return: 
        """

        resource_package = __name__
        resource_path = '../certs/data/cacert.pem'
        return pkg_resources.resource_string(resource_package, resource_path)

    def report(self):
        """
        pass
        :return: 
        """
        ct = time.time()
        if ct - self.state_last_dump < self.state_time_dump:
            return

        logger.debug('.. rsa: %s, non-rsa: %s, errs: %s, nofpr: %s, nor: %s, exp: %s, found: %s, not CA:'
                     ' %s, mem: %s MB, depth: %s, cfile: %s'
                     % (self.num_rsa, self.num_non_rsa, self.num_errs, self.num_no_fprint_raw, self.num_no_raw,
                        self.num_expired, self.num_found, self.num_not_ca,
                        utils.get_mem_mb(), self.cur_depth, self.cur_file))
        self.state_last_dump = ct

    def test_cert(self, cert, js=None, aux=None):
        """
        Test der x509 certificate
        :param js: 
        :return: 
        """
        if self.fmagic is None:
            return

        try:
            pub = cert.public_key()
            if not isinstance(pub, RSAPublicKey):
                self.num_non_rsa += 1
                return

            pubnum = cert.public_key().public_numbers()
            self.num_rsa += 1

            xres = self.fmagic.magic16(['%x' % pubnum.n])
            if len(xres) > 0:
                self.num_found += 1
                logger.error('!!!!!!!!!!!!!!!!!!!!!!!!! JS: %s, aux: %s' % (utils.try_get_cname(cert), aux))
                logger.info(js)

        except Exception as e:
            logger.error('Exception testing certificate: %s' % e)
            self.trace_logger.log(e)

    def roots(self, fname):
        """
        One root file processing
        :param fname: 
        :return: 
        """
        self.cur_file = fname
        before_file_certs_size = len(self.all_certs)
        with open(fname) as fh:
            for line in fh:
                try:
                    if '"ca": false' in line:
                        continue
                        
                    js = json.loads(line)
                    fprint = None
                    raw = None
                    rawb = None

                    if 'fprint' in js:
                        fprint = js['fprint']

                    if 'ca' in js and not js['ca']:
                        continue

                    fprint_requires_raw = fprint is None or len(fprint) != 40
                    if fprint_requires_raw and 'raw' not in js:
                        self.num_no_fprint_raw += 1
                        continue

                    if fprint_requires_raw:
                        raw = js['raw']
                        rawb = base64.b64decode(raw)
                        fprint = hashlib.sha1(rawb).hexdigest()

                    # Already seen in this round, may become valid in the next round.
                    if fprint in self.chain_cert_db:
                        continue

                    # Already assigned to a trust category
                    if fprint in self.assigned_fprints:
                        continue

                    if 'raw' not in js:
                        self.num_no_raw += 1
                        continue

                    if rawb is None:
                        raw = js['raw']
                        rawb = base64.b64decode(raw)

                    self.chain_cert_db.add(fprint)
                    crypt_cert = load_der_x509_certificate(rawb, get_backend())

                    if not utils.try_is_ca(crypt_cert):
                        if self.num_not_ca % 1000 == 0:
                            logger.debug('Cert is not CA: %s (%d)' % (fprint, self.num_not_ca))
                        self.num_not_ca += 1
                        continue

                    # Verify
                    ossl_cert = load_certificate(FILETYPE_ASN1, rawb)
                    self.cur_store.set_flags(0x200000)
                    store_ctx = X509StoreContext(self.cur_store, ossl_cert)
                    try:
                        store_ctx.verify_certificate()
                        self.interms[self.cur_depth].append(js)
                        self.assigned_fprints.add(fprint)
                        self.all_certs.append(ossl_cert)
                        self.test_cert(crypt_cert, js)

                    except X509StoreContextError as cex:
                        self.trace_logger.log(cex, custom_msg='Exc in verification')
                        if isinstance(cex.message, (types.ListType, types.TupleType)):
                            if cex.message[0] == 10:
                                self.num_expired += 1
                                self.test_cert(crypt_cert, js, 'Expired')

                    except Exception as e:
                        self.trace_logger.log(e, custom_msg='General Exc in verification')

                    self.report()
                    
                except Exception as e:
                    logger.error('Exception in processing certs %s' % e)
                    self.trace_logger.log(e)
                    self.num_errs += 1
        new_certs_size = len(self.all_certs) - before_file_certs_size
        logger.info('File %s contributed with %s certificates' % (fname, new_certs_size))

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        roots = self.load_roots()
        logger.info('Roots loaded')

        # 1 - load all CAs, roots from Mozilla.
        roots = roots.split('-----END CERTIFICATE-----')
        for root in roots:
            if len(root.strip()) == 0:
                continue
            try:
                root += '-----END CERTIFICATE-----'
                root_cert = load_certificate(FILETYPE_PEM, root)
                crypt_cert = load_pem_x509_certificate(root, get_backend())
                self.root_store.add_cert(root_cert)
                self.cur_store.add_cert(root_cert)
                self.all_certs.append(root_cert)
                root_fprint = binascii.hexlify(crypt_cert.fingerprint(hashes.SHA1()))
                self.assigned_fprints.add(root_fprint)
                self.test_cert(crypt_cert)
                logger.info('Root: %s' % root_fprint)

            except Exception as e:
                logger.error('Exception in processing root cert %s' % e)
                self.trace_logger.log(e)

        logger.info('Roots[%s] %s' % (len(self.all_certs), self.root_store))

        root_files = []
        for tlsdir in self.args.tlsdir:
            root_files += sorted([os.path.join(tlsdir, f) for f in os.listdir(tlsdir)
                            if (os.path.isfile(os.path.join(tlsdir, f)) and '.cr.json' in f)])

        for alexa in self.args.alexa:
            root_files += sorted([os.path.join(alexa, f) for f in os.listdir(alexa)
                            if (os.path.isfile(os.path.join(alexa, f)) and '.cr.json' in f)])

        for sonar in self.args.sonar:
            root_files += sorted([os.path.join(sonar, f) for f in os.listdir(sonar)
                            if (os.path.isfile(os.path.join(sonar, f)) and '_certs.uniq.json' in f)])

        for sonar in self.args.sonar_snap:
            root_files += sorted([os.path.join(sonar, f) for f in os.listdir(sonar)
                            if (os.path.isfile(os.path.join(sonar, f)) and '_merge_certs.uniq.json' in f)])

        for fl in root_files:
            logger.debug('File: %s' % fl)

        # BFS on CA tree
        for cdepth in range(1, 10):
            logger.info('New depth level: %d' % cdepth)
            self.cur_depth = cdepth
            self.interms[cdepth] = []
            self.chain_cert_db = set()

            for fidx, fname in enumerate(root_files):
                logger.info('Reading file[%02d][%02d/%02d] %s' % (self.cur_depth, fidx+1, len(root_files), fname))
                self.roots(fname)

            self.cur_store = self.new_store()
            for crt in self.all_certs:
                try:
                    self.cur_store.add_cert(crt)
                except:
                    pass

            ln = len(self.interms[self.cur_depth])
            if ln == 0:
                logger.info('No more certs added, exiting')
                break

            logger.info('New certificates added: %s' % ln)
            dpath = os.path.join(self.args.data_dir, 'interm-lvl%02d.json' % cdepth)
            with open(dpath, 'w') as fh:
                for rec in self.interms[cdepth]:
                    fh.write('%s\n' % json.dumps(rec))

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Censys TLS dataset - generates intermediates CA DB')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--sec', dest='sec', default=False, action='store_const', const=True,
                            help='Security scan')

        parser.add_argument('--dry-run', dest='dry_run', default=False, action='store_const', const=True,
                            help='Dry run - no file will be overwritten or deleted')

        parser.add_argument('--tlsdir', dest='tlsdir', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Directory with TLS results to process')

        parser.add_argument('--alexa', dest='alexa', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Directory with Alexa results to process')

        parser.add_argument('--sonar', dest='sonar', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Sonar SSL dir with *_certs.uniq.json files, json per line, raw record for cert')

        parser.add_argument('--sonar-snap', dest='sonar_snap', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Sonar SSL dir with snapshots - _merge_certs.uniq.json')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        if self.args.sec:
            import sec
            self.fmagic = sec.Fprinter()

        self.work()


def main():
   app = IntermediateBuilder()
   app.main()


if __name__ == '__main__':
    main()


