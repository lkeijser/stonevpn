#!/usr/bin/env python

from distutils.core import setup, Command
import os, sys
from StoneVPN_App import STONEVPN_VERSION

class SetupBuildCommand(Command):
    user_options = []
    def initialize_options(self):
        self._dir = os.getcwd()
    def finalize_options(self):
        pass

class InstallDocsCommand(SetupBuildCommand):
    """
    Extra command to install documentation files
    """
    description = "install documentation and sample configuration files"
    def run(self):
        import shutil
        doc_files=(
                ('share/StoneVPN',['README','COPYING','Changelog','TODO']),
                ('share/StoneVPN/example',['conf/stonevpn.conf']),
                ('share/StoneVPN/rpm',['rpm/stonevpn.spec']),
                ('share/man/man1',['man/stonevpn.1']),
                ('share/man/man5',['man/stonevpn.conf.5'])
            )
        for dst_path,files in doc_files:
            for src in files:
                filename = str(src.split('/')[len(src.split('/'))-1])
                print "copying %s to /usr/%s/%s" % (src,dst_path,filename)
		if not os.path.isdir('/usr/' + str(dst_path)):
		    os.mkdir('/usr/' + str(dst_path))
                shutil.copy(src, '/usr/' + str(dst_path) + "/" + str(filename))
        cmd = 'gzip /usr/share/man/man1/stonevpn.1'
        os.system(cmd)
        cmd = 'gzip /usr/share/man/man5/stonevpn.conf.5'
        os.system(cmd)

# Generate list of files
files=[]
for f in os.path.abspath(''):
    files.append(f)

setup(name = 'stonevpn',
    version = STONEVPN_VERSION,
    description = 'Easy OpenVPN certificate and configuration management',
    long_description = 'StoneVPN is a system that makes it easy to create certificates and configuration files for use with an OpenVPN server for Windows, Linux and Mac users. It has the ability to create a zip file and e-mail the entire package to a user. It uses pyOpenSSL, and the latest version of it allows it to manage a CRL file.',
    author = 'Leon Keijser',
    author_email = 'leon@gotlinux.nl',
    url = 'http://github.com/lkeijser/stonevpn/tree/master',
    download_url = 'http://github.com/lkeijser/stonevpn/downloads',
    license = 'GPLv2+',
    packages = ['StoneVPN'],
    package_data = {'stonevpn': files},
    scripts = ["bin/stonevpn"],
    data_files=[
        ('/etc',['conf/stonevpn.conf']),
        ],
    cmdclass = { 'install_docs': InstallDocsCommand }
    ),
