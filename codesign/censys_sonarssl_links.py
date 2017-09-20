#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Processing censys sonarssl link page to the json
https://scans.io/study/sonar.ssl
"""

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
import utils
import coloredlogs
import time
import input_obj
from lxml import html
from datetime import datetime


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class Link(object):
    """
    Represents one performed test and its result.
    """
    def __init__(self, file_name=None, file_href=None, file_size=None, file_hash=None):
        self.file_name = file_name
        self.file_href = file_href
        self.file_size = file_size
        self.file_hash = file_hash

    def to_json(self):
        js = collections.OrderedDict()
        js['name'] = self.file_name
        js['href'] = self.file_href
        js['size'] = self.file_size
        js['hash'] = self.file_hash
        return js


def main():
    """
    Processing censys link page to the json
    https://scans.io/study/sonar.ssl
    :return:
    """
    parser = argparse.ArgumentParser(description='Processes SonarSSL links from the page, generates json')

    parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='censys links')

    parser.add_argument('file', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='censys link file')

    args = parser.parse_args()

    # Process the input

    dataset_idx = 10
    datasets = {}

    input_objects = []
    for file_name in args.file:
        input_objects.append(input_obj.FileInputObject(file_name))
    for url in args.url:
        input_objects.append(input_obj.LinkInputObject(url))

    if len(input_objects) == 0:
        print('Error; no input given')
        sys.exit(1)

    for iobj in input_objects:
        logger.info('Processing %s' % iobj)

        with iobj:
            data = iobj.text()
            tree = html.fromstring(data)
            tables = tree.xpath('//table')

            if len(tables) == 0:
                logger.error('Parsing problems, no tables given')
                continue

            for tbl_idx, table in enumerate(tables):
                rows = table[1]  # tbody
                rows_cnt = len(rows)
                if rows_cnt < 2:
                    logger.warning('Table %d has not enough rows: %d' % (tbl_idx, rows_cnt))
                    continue

                for row_idx, row in enumerate(rows):
                    if row[0].tag != 'td':
                        continue

                    file_href = row[0][0].attrib['href'].strip()
                    file_name = row[0][0].text_content().strip()
                    file_hash = row[2].text_content().strip()
                    file_size = row[3].text_content().strip()
                    file_date = row[4].text_content().strip()

                    if file_date not in datasets:
                        dataset = collections.OrderedDict()
                        dataset['id'] = dataset_idx
                        dataset['date'] = file_date
                        dataset['date_utc'] = utils.unix_time(datetime.strptime(file_date, '%Y-%m-%d'))
                        dataset['files'] = collections.OrderedDict()
                        datasets[file_date] = dataset
                        dataset_idx += 1
                    else:
                        dataset = datasets[file_date]

                    link = Link(file_name, file_href, file_size, file_hash)
                    dataset['files'][file_name] = link.to_json()

    js = collections.OrderedDict()
    js['generated'] = time.time()
    js['data'] = sorted([datasets[x] for x in datasets], key=lambda x: x['id'])
    print(json.dumps(js, indent=2))


if __name__ == '__main__':
    main()




