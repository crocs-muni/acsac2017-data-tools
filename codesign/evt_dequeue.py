#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Event dequeue
"""

import os
import sys
import inspect
import resource

from requests.auth import HTTPBasicAuth

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import logging
import coloredlogs
import traceback
import math
import random
import time
import time
import signal
import utils
import collections
import threading
from threading import Lock as Lock
import types
import Queue


logger = logging.getLogger(__name__)


class EvtDequeue(object):
    """
    Class for sampling events in time.
    Protected by the lock.
    """
    LIMIT = 5*60.0

    __slots__ = ['dequeue', 'disabled']

    def __init__(self, *args, **kwargs):
        self.dequeue = collections.deque()
        self.disabled = False

    def len(self):
        return len(self.dequeue)

    def __len__(self):
        return self.len()

    def __str__(self):
        return str(self.dequeue)

    def __repr(self):
        return str(self.dequeue)

    def to_list(self):
        """
        Copies dequeue to the list. Shallow copy.
        :return:
        """
        return list(self.dequeue)

    def append(self, x):
        if self.disabled:
            return
        self.dequeue.append(x)

    def extend(self, lst):
        if self.disabled:
            return
        for x in lst:
            self.dequeue.append(x)

    def pop(self):
        self.dequeue.pop()

    def popleft(self):
        self.dequeue.popleft()

    def maintain(self, limit=None):
        """
        Maintains dequeue - removes old elements under the limit
        :return:
        """
        cur_time = time.time()
        if limit is None:
            limit = self.LIMIT

        thr = cur_time - limit

        if len(self.dequeue) == 0:
            return

        # Remove oldest elements. Oldest are on the left side of the queue.
        try:
            while len(self.dequeue) > 0 and self.dequeue[0] < thr:
                self.dequeue.popleft()
        except Exception as e:
            logger.error('Queue flush exception %s' % e)
            logger.debug(traceback.format_exc())

    def insert(self, cur_time=None):
        """
        Inserts new event to the dequeue
        :return:
        """
        if self.disabled:
            return

        if cur_time is None:
            cur_time = int(time.time())
        self.dequeue.append(cur_time)

    def under_limit(self, timeout):
        """
        Returns number of events done in last <timeout> seconds
        :param timeout:
        :return:
        """

        was_array = isinstance(timeout, types.ListType)
        timeouts = timeout if was_array else [timeout]
        results = [0] * len(timeouts)

        if len(self.dequeue) == 0:
            return results if was_array else results[0]

        now = time.time()
        lst = list(self.dequeue)
        num = 0
        for cur in reversed(lst):
            delta = now - cur
            skipped = 0
            for idx, tmo in enumerate(timeouts):
                if delta <= tmo:
                    results[idx] += 1
                else:
                    skipped += 1
            if skipped == len(timeouts):
                break

        return results if was_array else results[0]
