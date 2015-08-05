#!/usr/bin/env python
from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

long_description = "Lab Blog with IPython notebooks and git."


setup(
    name='labloid',
    version='0.1.0.dev5',
    description="Lab Blog with IPython notebooks and git",
    long_description=long_description,
    author='Edgar Walker & Fabian Sinz',
    author_email='',
    license = "MIT",
    url='https://github.com/labloid/labloid',
    keywords='blog software',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    install_requires=['flask', 'flask-bootstrap', 'flask-sqlalchemy', 'sqlalchemy', 'flask-manager', 'flask-script',
                      'flask-login', 'flask-sslify'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3 :: Only',
        'License :: OSI Approved :: MIT License',
    ],
)
