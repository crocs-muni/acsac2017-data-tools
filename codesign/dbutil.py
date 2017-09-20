#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import utils as util
import errors
import logging
import copy
import collections
import time
import types

from sqlalchemy import create_engine, UniqueConstraint, ColumnDefault
from sqlalchemy import exc as sa_exc
from sqlalchemy import case, literal_column, orm
from sqlalchemy.sql import expression
from sqlalchemy.ext.compiler import compiles
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, query
from sqlalchemy.orm.session import make_transient
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import INTEGER
import sqlalchemy as sa
from warnings import filterwarnings
import MySQLdb as MySQLDatabase


"""
Basic database utils.
"""

logger = logging.getLogger(__name__)


#
# DB helper objects
#  - query building, model comparison, projections
#


class TransientCol(object):
    """
    Represents transient column for model projection and comparison.
    """
    def __init__(self, name, default=None):
        self.name = name
        self.default = default


class ColTransformWrapper(object):
    """
    Simple column wrapper - for transformation
    """
    __slots__ = ('_col', '_tran')

    def __init__(self, col, transform=None):
        self._col = col
        self._tran = transform

    def transform(self, val):
        if self._tran:
            return self._tran(val)
        return val

    @property
    def col(self):
        return self._col

    def __getitem__(self, item):
        return self._col[item]

    def __getattr__(self, item):
        if item in self.__slots__:
            return object.__getattr__(self, item)
        return getattr(self._col, item)

    def __setattr__(self, key, value):
        if key in self.__slots__:
            return object.__setattr__(self, key, value)
        return setattr(self._col, key, value)

    def __repr__(self):
        return repr(self._col)


class DbHelper(object):
    """
    Helper methods
    """
    @staticmethod
    def default_value(col):
        """
        Returns default value from the column
        :param col:
        :return:
        """
        if col is None or col.default is None:
            return None

        if isinstance(col.default, ColumnDefault) and col.default.is_scalar:
            return col.default.arg

        if isinstance(col, TransientCol):
            return col.default

        return None

    @staticmethod
    def default_model(obj, projection=None, clone=False):
        """
        Fills in default model data from the passed object - fills in missing values.
        If projection is given the model is projected. Does not support function defaults.
        :param obj: object to fill in default values to
        :param projection: iterable of columns to check for the default value
        :param clone: if true the result is deepcloned from the original - does not modify the original object
        :return:
        """
        if obj is None:
            return None

        if clone:
            obj = copy.deepcopy(obj)

        cols = projection
        if cols is None or len(cols) == 0:
            cols = obj.__table__.columns

        for col in cols:
            val = getattr(obj, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            if val is None:
                def_val = DbHelper.default_value(col)
                if def_val is not None:
                    val = copy.deepcopy(def_val)
                    if isinstance(col, ColTransformWrapper):
                        val = col.transform(val)
                    setattr(obj, col.name, val)

        return obj

    @staticmethod
    def transform_model(obj, cols):
        """
        Transforms model with ColTransformWrapper cols
        :param obj:
        :param cols:
        :return:
        """
        if obj is None:
            return None
        if cols is None:
            return obj

        for col in cols:
            if not isinstance(col, ColTransformWrapper):
                continue

            val = getattr(obj, col.name)
            val = col.transform(val)
            setattr(obj, col.name, val)
        return obj

    @staticmethod
    def project_model(obj, projection, default_vals=False):
        """
        Projection returns tuple of the columns in the projection.
        :param obj:
        :param projection: iterable of columns to take to the projection
        :param default_vals: sets default values
        :return:
        """
        ret = []
        if obj is None:
            return None

        if projection is None or len(projection) == 0:
            return ()

        for col in projection:
            val = getattr(obj, col.name)
            if default_vals and val is None:
                def_val = DbHelper.default_value(col)
                if def_val is not None:
                    val = copy.deepcopy(def_val)

            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)
            ret.append(val)
        return tuple(ret)

    @staticmethod
    def set_if_none(obj, cols, val):
        """
        Sets val to the obj.col if the current value is null.
        Set is done in-place.
        :param obj:
        :param cols:
        :param val:
        :return:
        """
        if obj is None or cols is None:
            return None

        if not isinstance(cols, list):
            cols = list([cols])

        for col in cols:
            cval = getattr(obj, col.name)
            if cval is None:
                setattr(obj, col.name, val)

    @staticmethod
    def query_filter_model(q, cols, obj):
        """
        Adds filter to the query based on the cols & model
        :param q:
        :param cols:
        :param obj:
        :return:
        """
        for col in cols:
            val = getattr(obj, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            q = q.filter(col == val)
        return q

    @staticmethod
    def model_to_cmp_tuple(x, cols):
        """
        Returns model tuple for comparison, defined by cols projection
        :param x:
        :param cols:
        :return:
        """
        if x is None:
            return None
        return DbHelper.project_model(x, cols, default_vals=True)

    @staticmethod
    def models_tuples(x, y, cols):
        """
        Converts models to comparison tuples defined by the projection
        :param x:
        :param y:
        :param cols:
        :return:
        """
        return DbHelper.model_to_cmp_tuple(x, cols), DbHelper.model_to_cmp_tuple(y, cols)

    @staticmethod
    def models_tuples_compare(x, y, cols):
        """
        Converts models to comparison tuples defined by the projection and compares them
        :param x:
        :param y:
        :param cols:
        :return:
        """
        t1, t2 = DbHelper.models_tuples(x, y, cols)
        return t1 == t2

    @staticmethod
    def update_model_null_values(dst, src, cols):
        """
        Updates all fields with null values in dst from src defined by cols
        :param dst:
        :param src:
        :param cols:
        :return: number of changes
        """
        ret = []
        if dst is None or src is None:
            return 0

        if cols is None or len(cols) == 0:
            return 0

        changes = 0
        for col in cols:
            val = getattr(src, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            dstval = getattr(dst, col.name)
            if isinstance(col, ColTransformWrapper):
                dstval = col.transform(dstval)

            if dstval is None:
                setattr(dst, col.name, val)

            changes += 1
        return changes

    @staticmethod
    def yield_limit(qry, pk_attr, maxrq=100):
        """specialized windowed query generator (using LIMIT/OFFSET)

        This recipe is to select through a large number of rows thats too
        large to fetch at once. The technique depends on the primary key
        of the FROM clause being an integer value, and selects items
        using LIMIT."""

        firstid = None
        while True:
            q = qry
            if firstid is not None:
                q = qry.filter(pk_attr > firstid)
            rec = None
            for rec in q.order_by(pk_attr).limit(maxrq):
                yield rec
            if rec is None:
                break
            firstid = pk_attr.__get__(rec, pk_attr) if rec else None

    @staticmethod
    def get_count(q):
        """
        Gets count(*) from the given query, faster than .count() method:
         - q.count()      SELECT COUNT(*) FROM (SELECT ... FROM TestModel WHERE ...) ...
         - get_count(q)   SELECT COUNT(*) FROM TestModel WHERE ...
        :param q:
        :return:
        """
        count_q = q.statement.with_only_columns([func.count()]).order_by(None)
        count = q.session.execute(count_q).scalar()
        return count

    @staticmethod
    def to_dict(model, cols=None):
        """
        Transforms model to a dictionary
        :param model:
        :param cols:
        :return:
        """
        if model is None:
            return None

        if cols is None:
            cols = model.__table__.columns
        ret = collections.OrderedDict()

        for col in cols:
            val = getattr(model, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)

            if val is None:
                def_val = DbHelper.default_value(col)
                if def_val is not None:
                    val = copy.deepcopy(def_val)
                    if isinstance(col, ColTransformWrapper):
                        val = col.transform(val)

            ret[col.name] = val
        return ret

    @staticmethod
    def try_unpack_column(val, col):
        """
        Tries to deserialize packed column.
        E.g. for datetime tries to build back datetime object from timestamp
        :param val:
        :param col:
        :return:
        """
        if val is None or col is None:
            return None

        if isinstance(col.type, DateTime):
            if util.is_string(val):
                return util.defval(util.try_parse_datetime_string(val), val)
            elif util.is_number(val):
                return util.defval(util.try_get_datetime_from_timestamp(val), val)

        return val

    @staticmethod
    def to_model(obj, model=None, cols=None, ret=None, unpack_cols=False):
        """
        Transforms dict model to the desired model by extracting cols from it.
        Does not set default values, those are left intact
        :param obj: object to read from
        :param model: model class
        :param cols: columns collection
        :param ret: model to fill in, None by default (new is created from model class)
        :param unpack_cols: e.g., if datetime column tries to build datetime object from the current value in the field
        :return:
        """
        if model is None and ret is not None:
            model = ret.__class__
        if cols is None:
            cols = model.__table__.columns
        if ret is None:
            ret = model()

        for col in cols:
            val = obj[col.name] if col.name in obj else None
            if unpack_cols:
                val = DbHelper.try_unpack_column(val, col)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)
            setattr(ret, col.name, val)
        return ret

    @staticmethod
    def clone_model(s, obj):
        """
        Clones model with visitor function support for clonning transient fields.
        New model is detached from all sessions retaining all values.
        :param s:
        :param obj:
        :return:
        """
        if obj is None:
            return None
        model = obj.__class__
        cols = model.__table__.columns
        ret = copy.copy(obj)

        def sub_clone(obj):
            return DbHelper.clone_model(s, obj)

        def visit(obj):
            if isinstance(obj, types.ListType):
                return [visit(x) for x in obj]
            elif isinstance(obj, types.DictionaryType):
                return {k: visit(obj[k]) for k in obj}
            elif hasattr(obj, 'visit_fnc'):
                rt2 = obj.visit_fnc(visit)
                return rt2 if rt2 == ret else sub_clone(rt2)
            # elif obj != ret and isinstance(obj, Base):
            #     return sub_clone(obj)
            else:
                return obj
        ret = visit(ret)

        for col in cols:
            val = getattr(obj, col.name)
            if isinstance(col, ColTransformWrapper):
                val = col.transform(val)
            setattr(ret, col.name, val)
        return ret

    @staticmethod
    def detach(s, obj):
        """
        Detaches object from the session.
        :param s:
        :param obj:
        :return:
        """
        def rt_detach(obj):
            try:
                s.expunge(obj)
            except:
                pass
            return obj

        def sub_detach(obj):
            return DbHelper.detach(s, obj)

        def rec_detach(obj2):
            if isinstance(obj2, types.ListType):
                return [rec_detach(x) for x in obj2]
            elif isinstance(obj2, types.DictionaryType):
                return {k: rec_detach(obj2[k]) for k in obj2}
            elif hasattr(obj2, 'visit_fnc'):
                ret = obj2.visit_fnc(rec_detach)
                return ret if ret == obj else sub_detach(ret)
            # elif obj2 != obj and isinstance(obj2, Base):
            #     return sub_detach(obj2)
            # elif isinstance(obj2, Base):
            #     return rt_detach(obj2)
            else:
                return obj2

        return rec_detach(obj)


class DbException(errors.Error):
    """Generic DB exception"""
    def __init__(self, message=None, cause=None):
        super(DbException, self).__init__(message=message, cause=cause)


class DbTooManyFails(DbException):
    """Generic DB exception"""
    def __init__(self, message=None, cause=None):
        super(DbTooManyFails, self).__init__(message=message, cause=cause)


class ModelUpdater(object):
    """
    Generic helper with read/inserts
    """
    @staticmethod
    def load_or_insert(s, obj, select_cols, fetch_first=True, attempts=5):
        """
        General load if exists / store if not approach with attempts.
        :param s:
        :param obj:
        :param select_cols:
        :param fetch_first:
        :param attempts:
        :return: Tuple[Object, Boolean]  - object new/loaded, is_new flag
        """
        for attempt in range(attempts):
            if not fetch_first or attempt > 0:
                if not attempt == 0:  # insert first, then commit transaction before it may fail.
                    s.commit()
                try:
                    s.add(obj)
                    s.commit()
                    return obj, 1

                except Exception as e:
                    s.rollback()

            sq = DbHelper.query_filter_model(s.query(obj.__table__), select_cols, obj)
            db_obj = sq.first()
            if db_obj is not None:
                return db_obj, 0

        raise DbTooManyFails('Could not load / store object')


class assign(expression.FunctionElement):
    name = 'assign'


# @compiles(assign)
# def generic_assign(element, compiler, **kw):
#     raise ValueError('Unsupported engine')


@compiles(assign)
def mysql_assign(element, compiler, **kw):
    arg1, arg2 = list(element.clauses)
    return "@%s := %s" % (
        compiler.process(arg1),
        compiler.process(arg2)
    )

