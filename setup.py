# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='noyb',
    version='1.0.0',
    description='Encrypts and syncs local files with Google Drive',
    long_description=readme,
    author='Petar Petrov',
    author_email='',
    url='',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)
