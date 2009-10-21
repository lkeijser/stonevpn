#!/usr/bin/env python

from distutils.core import setup
import os, sys

files=[]
for f in os.path.abspath(''):
    files.append(f)

setup(name = 'stonevpn',
    version = '0.4.3',
    description = 'Easy OpenVPN certificate and configuration management',
    long_description = 'StoneVPN is a system that makes it easy to create certificates and configuration files for use with an OpenVPN server for both Windows and Linux users. It has the ability to create a zip file and e-mail the entire package to a user. It uses pyOpenSSL and custom patches that allow it to manage a CRL file.',
    author = 'Leon Keijser',
    author_email = 'keijser@stone-it.com',
    url = 'http://github.com/lkeijser/stonevpn/tree/master',
    download_url = 'http://github.com/lkeijser/stonevpn/downloads',
    license = 'GPLv2+',
    packages = ['StoneVPN'],
    package_data = {'stonevpn': files},
    scripts = ["stonevpn"],
    data_files=[
        ('share/StoneVPN',['README','COPYING','Changelog','TODO']),
        ('share/StoneVPN/example',['conf/stonevpn.conf']),
        ('share/StoneVPN/patches',['patches/pyOpenSSL-0.9-crl.patch','patches/pyOpenSSL-0.9-pkcs12.patch']),
        ('share/StoneVPN/rpm',['rpm/stonevpn.spec']),
        ]
    )

