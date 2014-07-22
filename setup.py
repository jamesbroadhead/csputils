#!/usr/bin/env python

from distutils.core import setup

setup(name='csputils',
    version='0.1',
    description='csputils - helpers for writing Content-Security-Policy rules',
    author='jbroadhead',
    author_email='jbroadhead@twitter.com',
    url='https://github.com/jamesbroadhead/csputils.git',
    packages = ['csputils'],
    package_dir = {'': ''},
)
