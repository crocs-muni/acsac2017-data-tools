#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Fetch PGP keys from the key server in multithreaded manner
"""

import re
import os
import json
import argparse
import logging
import coloredlogs
import traceback
import datetime
import utils
import versions as vv
import threading
import itertools
import databaseutils
from collections import OrderedDict

from database import MavenArtifact, MavenSignature, PGPKey
from database import Base as DB_Base

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class PGPKeyFetch(object):
    """
    Fetch the pgp key
    """

    def __init__(self, config_file=None, sqlite=None, sqlite_data=False, use_json=False, *args, **kwargs):
        self.args = None
        self.terminate = False

        self.config = None
        self.config_file = config_file
        self.sqlite_file = sqlite
        self.sqlite_data = sqlite_data
        self.use_json = use_json

        self.stop_event = threading.Event()
        self.db_config = None
        self.engine = None
        self.session = None

        self.sqlite_engine = None
        self.sqlite_session = None

    def trigger_stop(self):
        """
        Sets terminal conditions to true
        :return:
        """
        self.terminate = True
        self.stop_event.set()

    def init_config(self):
        """
        Loads config & state files
        :return:
        """
        if self.config_file is None:
            return

        with open(self.config_file, 'r') as fh:
            self.config = json.load(fh, object_pairs_hook=OrderedDict)
            logger.info('Config loaded: %s' % os.path.abspath(self.config_file))

    def init_db(self):
        """
        Initializes database engine & session.
        Has to be done on main thread.
        :return:
        """
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker, scoped_session

        if self.config_file is not None:
            self.db_config = databaseutils.process_db_config(self.config['db'])

            self.engine = create_engine(self.db_config.constr, pool_recycle=3600)
            self.session = scoped_session(sessionmaker(bind=self.engine))

            # Make sure tables are created
            DB_Base.metadata.create_all(self.engine)

        elif self.sqlite_file is not None:
            dbname = 'sqlite:///%s' % self.sqlite_file
            self.engine = create_engine(dbname, echo=False)
            self.session = scoped_session(sessionmaker(bind=self.engine))
            DB_Base.metadata.create_all(self.engine)
            logger.info('Using SQLite %s' % self.engine)

    def work(self):
        logger.info('Starting...')
        self.init_config()
        self.init_db()
        logger.info('Database initialized')
        if not self.sqlite_data:
            return

        sess = self.session()
        buff = []

        batch_size = 10000
        iterator = itertools.chain(
            sess.query(MavenArtifact).yield_per(batch_size),
            sess.query(MavenSignature).yield_per(batch_size),
            sess.query(PGPKey).yield_per(batch_size)
        )

        for obj in iterator:
            sess.expunge(obj)
            buff.append(obj)

            if len(buff) > batch_size:
                self.flush_sqlite(buff)
                buff = []

        # Final flush
        self.flush_sqlite(buff)
        buff = []
        logger.info('Dump finished')

    def flush_sqlite(self, buff):
        if len(buff) == 0:
            logger.info('Buffer is empty')
            return

        if self.sqlite_file is None:
            logger.info('SQLite file is none')
            return

        if not self.sqlite_data:
            return

        s = self.sqlite_session()
        for elem in buff:
            s.merge(elem)

        logger.debug('Committing %d elems %s' % (len(buff), s))
        s.flush()
        s.commit()
        utils.silent_close(s)

    def main(self):
        parser = argparse.ArgumentParser(description='Maven data crawler')

        parser.add_argument('-c', dest='config', default=None,
                            help='JSON config file')

        parser.add_argument('-s', dest='sqlite', default=None,
                            help='SQlite file')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--keys', dest='keys', default=None,
                            help='JSON array with key IDs')

        parser.add_argument('--json', dest='json', default=None,
                            help='Big json file from pgp dump')

        parser.add_argument('-t', dest='threads', default=1, type=int,
                            help='Number of threads to use for downloading the keys')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.config_file = self.args.config
        self.sqlite_file = self.args.sqlite
        self.work()


def main():
    app = PGPKeyFetch()
    app.main()


if __name__ == '__main__':
    main()

