#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import collections

"""
Basic database utils.
"""


# Database credentials loaded from the DB config file
DatabaseCredentials = collections.namedtuple('DatabaseCredentials',
                                             ['constr', 'dbtype', 'host', 'port', 'dbfile',
                                              'user', 'passwd', 'db', 'dbengine', 'data'])


def find_db_config(base_name='db.json', dirs=None):
    """
    Finds database configuration file - looks in the current working directory and project directory.
    :param base_name: database configuration name
    :param dirs: directory list to explore
    :return: path to the config file or None if the config file was not found
    """
    file_dir = os.path.dirname(os.path.realpath(__file__))
    paths = []
    if dirs is not None:
        paths += dirs
    else:
        paths = [os.getcwd(), os.path.join(file_dir, '..'), file_dir]

    for cur_dir in paths:
        cur_file = os.path.join(cur_dir, base_name)
        if os.path.exists(cur_file):
            return cur_file

    return None


def json_or_default(js, key, defval=None):
    """
    Loads key from the JS if exists, otherwise returns defval
    :param js: dictionary
    :param key: key
    :param defval: default value
    :return:
    """
    if key not in js:
        return defval
    return js[key]


def process_db_config(js):
    """
    Loads database configuration from the passed dictionary
    :param js: db config dictionary
    :return: DatabaseCredentials
    """
    dbtype = json_or_default(js, 'dbtype', 'memory').strip().lower()
    host = json_or_default(js, 'host')
    port = json_or_default(js, 'port')
    db = json_or_default(js, 'db')
    user = json_or_default(js, 'user')
    passwd = json_or_default(js, 'passwd')
    dbfile = json_or_default(js, 'dbfile')
    dbengine = json_or_default(js, 'dbengine')

    # Build connection string
    con_string = None
    if dbtype in ['mysql', 'postgresql', 'oracle', 'mssql']:
        port_str = ':%s' % port if port is not None else ''
        host_str = host if host is not None else 'localhost'
        dbengine_str = '+%s' % dbengine if dbengine is not None else ''

        if user is None or passwd is None or db is None:
            raise ValueError('User, password and database are mandatory for DB type ' + dbtype)

        con_string = '%s%s://%s:%s@%s%s/%s' % (dbtype, dbengine_str, user, passwd, host_str, port_str, db)

    elif dbtype == 'sqlite':
        if dbfile is None:
            raise ValueError('Database file (dbfile) is mandatory for SQLite database type')

        con_string = 'sqlite:///%s' % (os.path.abspath(dbfile))

    elif dbtype == 'memory':
        con_string = 'sqlite://'

    else:
        raise ValueError('Unknown database type: ' + dbtype)

    creds = DatabaseCredentials(constr=con_string, dbtype=dbtype, host=host, port=port, dbfile=dbfile,
                                user=user, passwd=passwd, db=db, dbengine=dbengine, data=js)
    return creds


def load_db_config(config_file):
    """
    Loads config file from the config file path
    :param config_file: config file path
    :return: DatabaseCredentials
    """
    with open(config_file, 'r'):
        data = config_file.read()
        js = json.loads(data)
        return process_db_config(js)


