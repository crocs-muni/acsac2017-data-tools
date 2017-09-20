import sys

from setuptools import setup
from setuptools import find_packages

version = '0.0.0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'pycrypto>=2.6',
    'cryptography',
    'requests',
    'requests[socks]',
    'setuptools>=1.0',
    'six',
    'cmd2>=0.6.9',
    'psutil',
    'pid>=2.0.1',
    'blessed>=1.14.1',
    'future',
    'coloredlogs',
    'scipy',
    'numpy',
    'bitarray_ph4',
    'ufx',
    'pgpdump',
    'apk_parse_ph4>=0.1.7',
    'pyx509_ph4',
    'lxml',
    'SQLAlchemy',
    'mem_top',
    'pexpect',
    'dpkt',
    'py-lz4framed_ph4',
    'python-dateutil',
    'pyjks',
    # 'mpi4py'
]

dev_extras = [
    'nose',
    'pep8',
    'tox',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
    'sphinxcontrib-programoutput',
]

setup(
    name='acsac2017-muni',
    version=version,
    description='ACSAC 2017 tools',
    url='https://gitlab.fi.muni.cz/labak/acsac2017',
    author='Dusan Klinec',
    author_email='dusan.klinec@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
    }
)
