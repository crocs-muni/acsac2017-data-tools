#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import re
import types
from past.builtins import cmp


class Version(object):
    """
    Simple object representing version
    """
    def __init__(self, version):
        self.version = str(version)

    def __str__(self):
        return self.version

    def __repr__(self):
        return 'Version(%r)' % self.version

    def __hash__(self):
        return self.version.__hash__()

    def __cmp__(self, other):
        return version_cmp(Version.normalize(self.version), Version.normalize(other))

    def to_json(self):
        return self.version

    def trim(self, max_comp=None):
        self.version = version_trim(Version.normalize(self.version), max_comp)
        return self

    def pad(self, ln):
        self.version = version_pad(Version.normalize(self.version), ln)
        return self

    @staticmethod
    def normalize(x):
        return str(x).replace(':', '.')


def version_filter(objects, key=lambda x: x, min_version=None, max_version=None, exact_version=None):
    """
    Filters the objects according to the version criteria.
    :param objects: 
    :param key: 
    :param min_version: 
    :param max_version: 
    :param exact_version: 
    :return: array of objects matching all criteria given
    """
    ret = list(objects)

    if exact_version is not None:
        ret = [x for x in ret if version_cmp(key(x), exact_version, max_comp=version_len(exact_version)) == 0]

    if min_version is not None:
        ret = [x for x in ret if version_cmp(key(x), min_version, max_comp=version_len(min_version)) >= 0]

    if max_version is not None:
        ret = [x for x in ret if version_cmp(key(x), max_version, max_comp=version_len(max_version)) <= 0]

    return ret


def version_pick(objects, key=lambda x: x, pick_min=False, pick_max=False, max_comp=None):
    """
    Filters objects according to the version criteria.
    Picks either minimal version from the list or the maximal one
    :param objects: 
    :param key: 
    :param pick_min: 
    :param pick_max: 
    :param max_comp: 
    :return: array of objects with the same picked version
    """
    all_versions = set()
    for ver in objects:
        v = version_trim(key(ver), max_comp)
        all_versions.add(v)

    all_versions = list(all_versions)
    all_versions = sorted(all_versions, cmp=version_cmp)
    selected = None

    if pick_min:
        selected = all_versions[0]
    if pick_max:
        selected = all_versions[-1]

    return [x for x in objects if version_cmp(key(x), selected, max_comp=max_comp) == 0]


def version_len(a, version_delim='.'):
    """
    Returns number of version components
    :param a: 
    :param version_delim: 
    :return: 
    """
    if isinstance(a, types.ListType):
        return len(a)

    return len(a.split(version_delim))


def version_trim(a, max_comp=None):
    """
    Trims the version to the given length
    :param a: 
    :param max_comp: 
    :return: 
    """
    if max_comp is None:
        return a

    if isinstance(a, types.ListType):
        return a[:max_comp]

    p = a.split('.')
    return '.'.join(p[:max_comp])


def version_pad(a, ln):
    """
    Pads version with zeros to the given component length
    :param a: 
    :param ln: 
    :return: 
    """
    vlen = version_len(a)
    if vlen >= ln:
        return a

    if isinstance(a, types.ListType):
        return a + ([0] * (ln - vlen))

    p = a.split('.')
    return '.'.join(p + (['0'] * (ln - vlen)))


def version_cmp_norm(a, b, max_comp=None, version_delim='.'):
    """
    Version comparison - normalize
    :param a: 
    :param b: 
    :param max_comp: 
    :param version_delim: 
    :return: 
    """
    return version_cmp(a, b, max_comp, version_delim, normalize=True)


def version_split(v, version_delim='.', normalize=False):
    """
    Version split to base components
    :param v: 
    :param version_delim: 
    :param normalize: 
    :return: 
    """
    if isinstance(v, types.IntType):
        return [v]
    if isinstance(v, types.ListType):
        return v

    if normalize:
        v = Version.normalize(v)
    return v.split(version_delim)


def version_cmp(a, b, max_comp=None, version_delim='.', normalize=False):
    """
    Compares versions a, b lexicographically
    :param a: 
    :param b: 
    :param max_comp: maximal number of descent
    :param version_delim: version delimitier
    :param normalize: version delimitier
    :return: 
    """
    def v_split(x, delim):
        if isinstance(x, types.IntType):
            return [x]
        if isinstance(x, types.ListType):
            return x
        return x.split(delim)

    if normalize:
        a = Version.normalize(a)
        b = Version.normalize(b)

    parts_a = v_split(a, version_delim)
    parts_b = v_split(b, version_delim)
    cmp_len = max(len(parts_a), len(parts_b))

    # Pad with zeros so 5.3 < 5.3.4
    parts_a = version_pad(parts_a, cmp_len)
    parts_b = version_pad(parts_b, cmp_len)

    if max_comp is not None:
        cmp_len = min(cmp_len, max_comp)

    for idx in range(cmp_len):
        if version_delim == '.':
            cmp_res = version_cmp(parts_a[idx], parts_b[idx], max_comp=None, version_delim='-')
        else:
            cmp_res = cmp(int_if_int(parts_a[idx]), int_if_int(parts_b[idx]))

        if cmp_res == 0:
            continue
        return cmp_res

    # Tie
    return 0


def int_if_int(x):
    """
    Converts to integer if it is integral
    :param x: 
    :return: 
    """
    if isinstance(x, types.IntType):
        return x

    if re.match('^[0-9]+$', x):
        return int(x)

    return x

