"""

 StoneVPN - Easy OpenVPN certificate and configuration management

 (C) 2009,2010 by L.S. Keijser, <keijser@stone-it.com>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

"""

import commands
import fileinput
import getpass
import glob
import os
import random
import re
import shutil
import smtplib
import string
import sys
import time
import zipfile
from OpenSSL import SSL, crypto
from optparse import OptionParser, OptionGroup
from configobj import ConfigObj
from time import strftime
from datetime import datetime, timedelta
from IPy import IP
from string import atoi
from datetime import datetime
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import formatdate
from email import Encoders
from StoneVPN import STONEVPN_VERSION


def main():
    stonevpnconf = '/etc/stonevpn.conf'
    stonevpnver = STONEVPN_VERSION
    # Read main configuration from stonevpn.conf
    if os.path.exists(stonevpnconf):
        config = ConfigObj(stonevpnconf)
        sectionname = 'stonevpn conf'
        section=config[sectionname]
        
        crlfile = section['crlfile']
        prefix = section['prefix']
        pushrouter = section['pushrouter']
        cacertfile = section['cacertfile']
        cakeyfile = section['cakeyfile']
        openvpnconf = section['openvpnconf']
        ccddir = section['ccddir']
        working = section['working']
        opensslconf = section['opensslconf']
        ciphermethod = section['cipher']
        mail_server = section['mail_server']
        mail_cc = section['mail_cc']
        mail_msg = section['mail_msg']
        mail_from = section['mail_from']
        try:
            mail_passtxt = section['mail_passtxt']
        except:
            print "Missing variable 'mail_passtxt' in %s! Please update your configuration.\nHint: look at the example configuration file." % stonevpnconf
            sys.exit()
    else:
        print "File " + stonevpnconf + " does not exist!"
        sys.exit()

    # retrieve default expiration date from openssl.cnf, needed for optionparse 
    if os.path.exists(opensslconf):
        config = ConfigObj(opensslconf)
        sectionname = 'CA_default'
        section=config[sectionname]
        defaultDays = section['default_days']
    else:
        print "Error: OpenSSL configuration file not found at %s" % opensslconf
        sys.exit()

    # define some crypto stuff
    TYPE_RSA = crypto.TYPE_RSA
    TYPE_DSA = crypto.TYPE_DSA
    FILETYPE = crypto.FILETYPE_PEM

    # command line options
    parser = OptionParser(usage="%prog -f <filename> -n <commonname> [ OPTIONS ]",version="%prog " + stonevpnver)

    # define groups
    group_crl = OptionGroup(parser, "Certificate revocation options")
    group_general = OptionGroup(parser, "General options",
            "All general options are mandatory")
    group_extra = OptionGroup(parser, "Extra options",
            "To be used in conjunction with the general options.")
    group_info = OptionGroup(parser, "Information/printing options")
    group_test = OptionGroup(parser, "Test/experimental options",
            "Caution: use these options with care.")

    # define special case for action with optional argument
    def optional_arg(arg_default):
        def check_value(option,opt_str,value,parser):
            # check for remaining args. these shouldn't start with a '-'
            if parser.rargs and not parser.rargs[0].startswith('-'):
                val=parser.rargs[0]
                parser.rargs.pop(0)
            else:
                # return the default value for the argument
                val=arg_default
            # remove the argument from the list and return the remaining args back to parser
            setattr(parser.values,option.dest,val)
        return check_value

    # populate groups
    parser.add_option("-D", "--debug",
        action="count", 
        dest="debug",
        help="enable debugging output")
    group_general.add_option("-n", "--name",
        action="store",
        type="string",
        dest="cname",
        help="Common Name, use quotes eg.: \"CNAME\" and only alphanumeric characters")
    group_general.add_option("-f", "--file",
        dest="fname",
        help="write to file FNAME (no extension!)")
    group_general.add_option("-o", "--config",
        action="store",
        dest="confs",
        default="unix",
        help="create config files for [windows|unix|mac|all]")
    group_extra.add_option("-e", "--prefix",
        action="store",
        dest="fprefix",
        default=prefix,
        help="prefix (almost all) generated files. Default = " + str(prefix))
    group_extra.add_option("-z", "--zip",
        action="store_true",
        dest="zip",
        help="add all generated files to a ZIP-file")
    group_extra.add_option("-m", "--mail",
        action="store",
        type="string",
        dest="emailaddress",
        help="send all generated files to EMAILADDRESS")
    group_extra.add_option("-i", "--free-ip",
        action="store_true",
        dest="freeip", 
        help="locate and assign free ip")
    group_extra.add_option("-E", "--extrafile",
        action="append",
        dest="extrafile",
        help="include extra file(s) like documentation. Can be used multiple times")
    group_extra.add_option("-p", "--passphrase",
        action="callback",
        callback=optional_arg('please_prompt_me'),
        dest="passphrase",
        help="prompt for a passphrase when generating private key, or supply one on the commandline")
    group_extra.add_option("-M", "--mailpass",
        action="store_true",
        dest="mailpass",
        help="include passphrase in e-mail body (only useful with the '-m' option)")
    group_extra.add_option("-R", "--randpass",
        action="store",
        type="string",
        dest="randpass",
        help="generate a random password of RANDPASS characters (eg.: -R 8)")
    group_extra.add_option("-S", "--serverip",
        action="store",
        type="string",
        dest="server_ip",
        help="use this IP address for the server when generating the configuration file, overriding the one specified in stonevpn.conf")
    group_crl.add_option("-r", "--revoke",
        action="store",
        dest="serial",
        help="revoke certificate with serial SERIAL")
    group_extra.add_option("-u", "--route",
        action="append",
        dest="route",
        help="push extra route(s) to client. Specify multiple routes as: -u 192.168.1.1/32 -u 10.1.4.0/24") 
    group_crl.add_option("-l", "--listrevoked",
        action="store_true",
        dest="listrevoked",
        help="list revoked certificates")
    group_crl.add_option("-C", "--crl",
        action="store_true",
        dest="displaycrl",
        help="display CRL file contents")
    group_info.add_option("-a", "--listall",
        action="store_true",
        dest="listall",
        help="list all certificates")
    group_info.add_option("-s", "--showserial",
        action="store_true",
        dest="showserial",
        help="display current SSL serial number")
    group_info.add_option("-c", "--printcert",
        action="store",
        dest="printcert",
        help="prints information about a certficiate file")
    group_info.add_option("-d", "--printindex",
        action="store_true",
        dest="printindex",
        help="prints index file")
    group_extra.add_option("-x", "--expire",
        action="store",
        dest="expiredate",
        help="certificate expires in EXPIREDATE h(ours), d(ays) or y(ears). The default is " + str(defaultDays) + " days. Example usage: -x 2h")
    group_crl.add_option("-N", "--newcrl",
        action="store_true",
        dest="emptycrl",
        help="create an empty CRL file (or overwrite an existing one)")
    group_test.add_option("-t", "--test",
        action="store_true",
        dest="test",
        help="Danger, Will Robinson, Danger! test parameter - can do anything! Review source before executing!")

    # add optiongroups
    parser.add_option_group(group_general)
    parser.add_option_group(group_extra)
    parser.add_option_group(group_info)
    parser.add_option_group(group_crl)
    parser.add_option_group(group_test)

    # parse cmd line options
    (options, args) = parser.parse_args()

    s = StoneVPN()
    # values we got from optparse:
    s.debug         = options.debug
    s.cname         = options.cname
    s.fname         = options.fname
    s.confs         = options.confs
    s.fprefix       = options.fprefix
    s.zip           = options.zip
    s.emailaddress  = options.emailaddress
    s.freeip        = options.freeip
    s.passphrase    = options.passphrase
    s.mailpass      = options.mailpass
    s.randpass      = options.randpass
    s.extrafile     = options.extrafile
    s.server_ip     = options.server_ip
    s.serial        = options.serial
    s.route         = options.route
    s.listrevoked   = options.listrevoked
    s.displaycrl    = options.displaycrl
    s.listall       = options.listall
    s.showserial    = options.showserial
    s.printcert     = options.printcert
    s.printindex    = options.printindex
    s.expiredate    = options.expiredate
    s.emptycrl      = options.emptycrl
    s.test          = options.test
    # values we got from parsing the configuration file:
    s.cacertfile    = cacertfile
    s.cakeyfile     = cakeyfile
    s.openvpnconf   = openvpnconf
    s.ccddir        = ccddir
    s.working       = working
    s.opensslconf   = opensslconf
    s.pushrouter    = pushrouter
    s.ciphermethod  = ciphermethod
    s.prefix        = prefix
    s.crlfile       = crlfile
    s.mail_server   = mail_server
    s.mail_cc       = mail_cc
    s.mail_msg      = mail_msg
    s.mail_from     = mail_from
    s.mail_passtxt  = mail_passtxt
    s.stonevpnconf  = stonevpnconf
    # and all other variables
    s.TYPE_RSA      = TYPE_RSA
    s.TYPE_DSA      = TYPE_DSA
    s.FILETYPE      = FILETYPE
    s.stonevpnver   = stonevpnver

    # check for all args
    if len(sys.argv[1:]) == 0:
        parser.print_help()

    # check for valid args
    if options.fname is None and options.serial is not None and options.listrevoked is not None and options.listall is not None and options.showserial is not None and options.printcert is not None and options.printindex is not None and options.emptycrl is not None and options.test is not None:
        parser.error("Error: you have to specify a filename (FNAME)")
    else:
        # must..have..root..
        myId = commands.getstatusoutput('id -u')[1]
        if not myId == '0':
            print "Sorry, root privileges required for this action."
            sys.exit(0)
        else:
            s.run()

class StoneVPN:

    def __init__(self):
        """
        Constructor. Arguments will be filled in by optparse..
        """
        self.cname         = None
        self.fname         = None
        self.confs         = None
        self.fprefix       = None
        self.zip           = None
        self.emailaddress  = None
        self.freeip        = None
        self.passphrase    = None
        self.mailpass      = None
        self.randpass      = None
        self.extrafile     = None
        self.server_ip     = None
        self.serial        = None
        self.route         = None
        self.listrevoked   = None
        self.displaycrl    = None
        self.listall       = None
        self.showserial    = None
        self.printcert     = None
        self.printindex    = None
        self.expiredate    = None
        self.emptycrl      = None
        self.test          = None
        
    # Read certain vars from OpenSSL config file
    def readOpenSSLConf(self):
        config = ConfigObj(self.opensslconf)
        sectionname = 'req_distinguished_name'
        section=config[sectionname]
        # make these variables also global
        global countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitName, defaultDays, prefixdir, indexdb, serialfile
        # Check if certain sections in OpenSSL configfile are present, report if they're not
        try:
            countryName = section['countryName_default']
            if len(countryName) is 0: 
                print "Error: countryName_default is empty. Please edit %s first." % self.opensslconf
                sys.exit()
        except KeyError:
            print "Error: missing section 'countryName_default' in " + self.opensslconf
            sys.exit()
        try:
            stateOrProvinceName = section['stateOrProvinceName_default']
            if len(stateOrProvinceName) is 0: 
                print "Error: stateOrProvinceName_default is empty. Please edit %s first." % self.opensslconf
                sys.exit()
        except KeyError:
            print "Error: missing section 'stateOrProvinceName_default' in " + self.opensslconf
            sys.exit()
        try:
            localityName = section['localityName_default']
            if len(localityName) is 0: 
                print "Error: localityName_default is empty. Please edit %s first." % self.opensslconf
                sys.exit()
        except KeyError:
            print "Error: missing section 'localityName_default' in " + self.opensslconf
            sys.exit()
        try:
            organizationName = section['0.organizationName_default']
            if len(organizationName) is 0: 
                print "Error: 0.organizationName_default is empty. Please edit %s first." % self.opensslconf
                sys.exit()
        except KeyError:
            print "Error: missing section '0.organizationName_default' in " + self.opensslconf
            sys.exit()
        try:
            organizationalUnitName = section['organizationalUnitName_default']
            if len(organizationalUnitName) is 0: 
                print "Error: organizationalUnitName_default is empty. Please edit %s first." % self.opensslconf
                sys.exit()
        except KeyError:
            print "Error: missing section 'organizationalUnitName_default' in " + self.opensslconf
            sys.exit()
        sectionname = 'CA_default'
        section=config[sectionname]
        defaultDays = section['default_days']
        prefixdir = section['dir']
        indexdb = section['database'].replace('$dir', prefixdir)
        serialfile = section['serial'].replace('$dir', prefixdir)

    def run(self):
        """
        StoneVPN's main function
        """

        if os.path.exists(self.opensslconf):
            self.readOpenSSLConf()
        else:
            print "File " + self.opensslconf + " does not exist!"
            sys.exit()

        # Check for presence of OpenSSL index file
        if not os.path.exists(indexdb):
            print "Error: indexfile not found at: " + indexdb + " or insufficient rights."
            sys.exit()

        # Check for presence of OpenSSL serial file
        if not os.path.exists(serialfile):
            print "Error: serialfile not found at: " + serialfile + " or insufficient rights."
            sys.exit()

        # Make sure FPREFIX ends with a dash
        if not self.fprefix == '':
            if not self.fprefix[-1] == '-':
                self.fprefix = str(self.fprefix) + '-'
        
        # check if working dir exists, create it if it doesn't
        if not os.path.exists(self.working):
            print "Working dir didn't exist, making ..."
            os.mkdir(self.working)
        # Make certificates
        if self.cname: 
            if self.fname is None:
                print "Error: required option -f/--file is missing."
                sys.exit()
            print "Creating " + self.fname + ".key and " + self.fname + ".crt for " + self.cname
            self.makeCert( self.fname, self.cname )

        # check for extra files to be included
        if self.extrafile:
            if self.fname is None or self.cname is None:
                print "Error: required option -f/--file and/or -n/--name is missing."
                sys.exit()
            for efile in self.extrafile:
                if os.path.exists(efile):
                    # copy them to a temp subdir within the working dir to avoid duplicates
                    try:
                        os.mkdir(self.working + '/' + self.fname + '-extrafiles')
                    except:
                        pass
                    print "Adding extra file %s" % efile
                    shutil.copy(efile, self.working + '/' + self.fname + '-extrafiles/')
                else:
                    # exit if the file wasn't found
                    print "Error: file %s was not found."
                    sys.exit()

        # Make nice zipfile from all the generated files
        # :: called only when option '-z' is used ::
        if self.zip:
            if self.fname is None or self.cname is None:
                print "Error: required option -f/--file and/or -n/--name is missing."
                sys.exit()
            print "Adding all files to " + self.working + "/" + self.fprefix + self.fname + ".zip"
            z = zipfile.ZipFile(self.working + "/" + self.fprefix + self.fname + ".zip", "w")
            for name in glob.glob(self.working + "/" + self.fprefix + self.fname + ".*"):
                # only add the files that begin with the name specified with the -f option, don't add the zipfile itself (duh)
                if not name == self.working + "/" + self.fprefix + self.fname + ".zip":
                    z.write(name, os.path.basename(name), zipfile.ZIP_DEFLATED)
            # and add the CA certificate file
            z.write(self.cacertfile, os.path.basename(self.cacertfile), zipfile.ZIP_DEFLATED)
            # check if extra files should be included as well
            if self.extrafile:
                for efile in self.extrafile:
                    z.write(efile, os.path.basename(efile), zipfile.ZIP_DEFLATED)
                # we can safely remove all files in the temp dir now since it was only used when not creating a zip file
                for file in glob.glob(self.working + "/" + self.fname + "-extrafiles/*"):
                    os.remove(file)
                # finally remove the temp dir itself
                os.rmdir(self.working + "/" + self.fname + "-extrafiles")
            z.close()
            # delete all the files generated, except the ZIP-file
            for file in glob.glob(self.working + "/" + self.fprefix + self.fname + ".*"):
                if not file == self.working + "/" + self.fprefix + self.fname + ".zip": os.remove(file)

        # Find free IP-address by parsing config files (usually in /etc/openvpn/ccd/*)
        # :: called only when option '-i' is used ::
        if self.freeip:
            if self.fname is None:
                print "Error: required option -f/--file is missing."
                sys.exit()
            print "Searching for free IP-address:"
            # see if vpn server conf file exists
            if not os.path.exists(self.openvpnconf):
                print "Error: OpenVPN server configuration file was not found at %s" % self.openvpnconf
                sys.exit()
            # parse config file in search for ifconfig-pool
            for line in fileinput.input(self.openvpnconf):
                if line.split()[0] == 'ifconfig-pool':
                    pool_from = line.split()[1]
                    pool_to = line.split()[2]
                    print "Pool runs from " + pool_from + " to " + pool_to
            # from here on we have to do some magic to get a list of
            # valid IP's in the specified pool
            # we first check if the first 3 octets in both 'from' and 'to'
            # are the same. 
            r = re.compile('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
            mFrom = r.match(pool_from)
            mTo = r.match(pool_to)
            if self.debug:
                print "DEBUG: first 3 octets of ip_from are %s.%s.%s" % (mFrom.group(1),mFrom.group(2),mFrom.group(3))
                print "DEBUG: first 3 octets of ip_to are %s.%s.%s" % (mTo.group(1),mTo.group(2),mTo.group(3))
            from_3octs = str(mFrom.group(1)) + '.' + str(mFrom.group(2)) + '.' + str(mFrom.group(3))
            to_3octs = str(mTo.group(1)) + '.' + str(mTo.group(2)) + '.' + str(mTo.group(3))
            if from_3octs == to_3octs:
                # ip's in pool are in a /24 (or higher, thus less addresses) subnet
                # create a range of valid ip's addresses and put them in a list
                if self.debug: print "DEBUG: both ip_from and ip_to are in the same subnet\nDEBUG: calculating range the 'easy' way.."
                range_4oct = range(int(mFrom.group(4)),int(mTo.group(4)))
                # fill range with ip's
                rangeIP = []
                for octet in range_4oct:
                    rangeIP.append(from_3octs + "." + str(octet))
            else:
                rangeIP = []
                # ip's in pool are not in a /24 subnet
                # we'll have to manually (well, kind of) calculate the range.
                range_3oct = range(int(mFrom.group(3)),int(mTo.group(3)))
                # append last octet since range() doesn't do that
                range_3oct.append(int(mTo.group(3)))
                if self.debug: print "DEBUG: range_3oct is %s" % range_3oct
                # the first element in the range is the starting octet and thus
                # we should look at the 4th octet now to determine the starting point
                for octet in range(int(mFrom.group(4)),255):
                    # fill rangeIP with valid ip's
                    rangeIP.append(from_3octs + "." + str(octet))
                # now remove the first octet from the range
                if self.debug: print "DEBUG: remove %s from %s" % (mFrom.group(3),range_3oct)
                range_3oct.remove(int(mFrom.group(3)))
                if self.debug: print "DEBUG: range_3oct is now %s" % range_3oct
                # now iterate over the rest, until we get to the last (3rd) octet
                for octet_3 in range_3oct:
                    if int(octet_3) != int(mTo.group(3)):
                        for octet in range(1,255):
                            rangeIP.append(mFrom.group(1) + '.' + mFrom.group(2) + '.' + str(octet_3) + '.' + str(octet))
                    else:
                        # this is the last (3rd) octet so only fill the list until the 4th octet of pool_to
                        for octet in range(1,int(mTo.group(4))):
                            rangeIP.append(mFrom.group(1) + '.' + mFrom.group(2) + '.' + str(mTo.group(3)) + '.' + str(octet))
            if self.debug: print "DEBUG: rangeIP is %s" % rangeIP
            # define list of IP-addresses
            ipList = []
            for x in rangeIP:
                ipList.append(x)
            # go through the individual config files to find IP-addresses
            for file in glob.glob(self.ccddir+"/*"):
                if self.debug: print "DEBUG: parsing file: " + file
                for line in fileinput.input(file):
                    # search for line that starts with 'ifconfig-push'
                    if line.split()[0] == 'ifconfig-push':
                        # the client IP is the 2nd argument ([2] is 0,1,2nd object on the line)
                        clientip = line.split()[2]
                        # remove IP from range if it exists in the list
                        if clientip in ipList:
                            ipList.remove(clientip) 
                        # the server IP is the 1st argument
                        servip = line.split()[1]
                        # remove IP from range if it exists in the list
                        if servip in ipList:
                            ipList.remove(servip)
            # sort list
            ipList.sort()
            # we now have a list of usable IP addresses :)
            # find 2 free IP-addresses:
            try:
                firstFree = ipList[0]
            except IndexError:
                print "Error: no free IP address left in pool!"
                sys.exit()
            try:
                secondFree = ipList[1]
            except IndexError:
                print "Error: no free IP address left in pool!"
                sys.exit()
            print "First free address: %s (local)" % firstFree
            print "Second free address: %s (peer)" % secondFree
            # check if ccd dir exists:
            if not os.path.exists(self.ccddir):
                print "Client configuration directory didn't exist, making ..."
                os.mkdir(self.ccddir)
            # And create the configuration file for these addresses
            nospaces_cname =  self.cname.replace(' ', '_')
            f=open(self.ccddir + '/' + nospaces_cname, 'w')
            f.write('ifconfig-push ' + str(secondFree) + ' ' + str(firstFree) + '\n')
            f.write('push "route ' + self.pushrouter + ' 255.255.255.255"\n')
            f.close()
            print "CCD file written to: %s\nPlease review or make additional changes."  % (self.ccddir + '/' + nospaces_cname)

        if self.listall:
            self.listAllCerts()

        if self.displaycrl:
            self.displayCRL()

        if self.listrevoked:
            self.listRevokedCerts()

        if self.serial:
            self.revokeCert(str(self.serial))

        if self.showserial:
            print "Current SSL serial number (in hex): " + self.readSerial()

        if self.printindex:
            print "Current index file (" + indexdb + "):"
            self.printIndexDB()

        if self.printcert:
            self.print_cert ( self.printcert )

        if self.emailaddress:
            if self.fname is None or self.cname is None:
                print "Error: required option -f/--file and/or -n/--name is missing."
                sys.exit()
            mail_attachment = []
            mail_to = self.emailaddress
            # First check if we've generated a ZIP file (include just one attachment) or not (include all generated files)
            if self.zip:
                mail_attachment.append(self.working + '/' + self.fprefix + self.fname + '.zip')
                self.send_mail(self.mail_from, mail_to, 'StoneVPN: generated files for ' + str(self.cname), self.mail_msg, mail_attachment)
            else:
                # Generate a list of filenames to include as attachments
                for name in glob.glob(self.working + "/" + self.fprefix + self.fname + ".*"):
                    mail_attachment.append(name)
                # Also include the CA certificate
                mail_attachment.append(self.cacertfile)
                # And check for extra files to be included
                if self.extrafile:
                    for efile in self.extrafile:
                        mail_attachment.append(efile)
                # Finally, send the mail
                self.send_mail(self.mail_from, mail_to, 'StoneVPN: generated files for ' + str(self.cname), self.mail_msg, mail_attachment)


        if self.route:
            if self.cname is None:
                print "Error: required option -n/--name is missing."
                sys.exit()
            IP.check_addr_prefixlen = False
            nospaces_cname =  self.cname.replace(' ', '_')
            clientfile = self.ccddir + "/" + nospaces_cname
            # nowwhat : 0=continue normally (append), 1=don't write clientfile, 2=overwrite)
            # setting to 'append' by default
            nowwhat=0
            if not self.freeip:
                if os.path.exists(clientfile):
                    overwrite=raw_input("Existing client configuration file was found. Do you want to (o)verwrite, (A)ppend or (s)kip): ")
                    if overwrite in ('o', 'O'):
                        os.remove(clientfile)
                        nowwhat=2
                    elif overwrite in ('s', 'S'):
                        nowwhat=1
            if self.debug: print "DEBUG: adding %s routes" % len(self.route)
            for newroute in self.route:
                try:
                    ip=IP(newroute)
                except ValueError:
                    print "Error: invalid prefix length given."
                    sys.exit()
                ip.NoPrefixForSingleIp = None
                ip.WantPrefixLen = 2
                if self.debug: print "DEBUG: ip: %s" % ip
                # check if supplied argument is an IPv4 address
                if IP(ip).version() != 4:
                    print "Error: only IPv4 addresses are supported."
                    sys.exit()
                route = str(ip).split('/')
                if self.debug:
                    if len(route) == 1:
                        print "DEBUG: only IP given, assume /32 netmask"
                # check if ccd dir exists:
                if not os.path.exists(self.ccddir):
                    print "Client configuration directory didn't exist, making ..."
                    os.mkdir(self.ccddir)
                f=open(self.ccddir + '/' + nospaces_cname, 'a')
                if self.debug: print "DEBUG: route: %s" % route
                if nowwhat == 1:
                    if self.debug: print "DEBUG: not writing route to client configfile!"
                # only write routes if we didn't skip overwriting/appending earlier
                if nowwhat != 1:
                    print "Adding route %s / %s" % (route[0],route[1])
                    f.write("push \"route " + route[0] + " " + route[1] + "\"\n")
                f.close()
            if nowwhat != 1:
                print "Wrote extra route(s) to " + self.ccddir + "/" + nospaces_cname
    
        if self.emptycrl:
            try:
                crl = crypto.CRL()
            except:
                print "\nError: CRL support is not available in your version of"
                print "pyOpenSSL. Please check the README file that came with"
                print "StoneVPN to see what you can do about this. For now, "
                print "you will have to revoke certificates manually.\n"
                sys.exit()
            if os.path.exists(self.crlfile):
                overwrite=raw_input("Existing crlfile was found. Do you want to overwrite (y/N): ") 
                if overwrite not in ('y', 'Y'):
                    print "Doing nothing.."
                    sys.exit()
            print "Creating empty CRL file at %s" % self.crlfile
            cacert = self.load_cert(self.cacertfile)
            cakey = self.load_key(self.cakeyfile)
            newCRL = crl.export(cacert, cakey, days=90)
            f=open(self.crlfile, 'w')
            f.write(newCRL)
            f.close()

        if self.test:
            print "Testing 1, 2, 5 ... three Sir!"
            sys.exit()

    # Create key
    def createKeyPair(self, type, bits):
        pkey = crypto.PKey()
        pkey.generate_key(type, bits)
        return pkey

    # Create request
    def createCertRequest(self, pkey, digest="md5", **name):
        req = crypto.X509Req()
        subj = req.get_subject()
        for (key,value) in name.items():
            setattr(subj, key, value)
        req.set_pubkey(pkey)
        req.sign(pkey, 'md5')
        return req

    # decimal 2 hexidecimal and vice versa
    def dec2hex(self, n):
        return "%X" % n

    def hex2dec(self, s):
        return int(s, 16)

    def printIndexDB(self):
        f=open(indexdb, 'r')
        for line in f:
            print line
        f.close()

    def readSerial(self):
        f=open(serialfile, 'r')
        serial = f.readline()
        f.close()
        return serial

    def writeSerial(self, serial):
        f=open(serialfile, 'w')
        f.write(serial)
        f.close()

    def writeIndex(self, index):
        f=open(indexdb, 'a')
        f.write(index)
        f.close()

    # Create certificate
    def createCertificate(self, req, (issuerCert, issuerKey), serial, (notBefore, notAfter), digest="md5"):
        extensions = []
        # Create the X509 Extensions
        extensions.append(crypto.X509Extension('basicConstraints',1, 'CA:FALSE'))
        try:
        	extensions.append(crypto.X509Extension('nsComment',0, 'Created with stonevpn ' + str(self.stonevpnver)))
        except ValueError:
        	print "\n=================================================================="
        	print "Warning: your version of pyOpenSSL doesn't support X509Extensions."
        	print "Please consult the README file that came with StoneVPN in order to"
        	print "fix this. This is not trivial. The certificate will be generated."
        	print "==================================================================\n"
        # We're creating a X509 certificate version 2
        cert = crypto.X509()
        cert.set_version ( 2 )
        # Add the Extension to the certificate
        cert.add_extensions(extensions)
        # Create a valid hexidecimal serial number
        goodserial = atoi(str(serial), 16)
        cert.set_serial_number(goodserial)
        if self.debug: print "DEBUG: notBefore is %s, notAfter is %s" % (notBefore,notAfter)
        #cert.gmtime_adj_notBefore(notBefore)
        #cert.gmtime_adj_notAfter(notAfter)
        now = datetime.utcnow().strftime("%Y%m%d%H%M%SZ")
        if self.debug: print "DEBUG: days is %s" % timedelta(seconds=notAfter)
        expire = (datetime.utcnow() + timedelta(seconds=notAfter)).strftime("%Y%m%d%H%M%SZ")
        cert.set_notBefore(now)
        cert.set_notAfter(expire)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(issuerKey, digest)
        return cert

    # Passphrase
    def getPass(self):
        passA = getpass.getpass('Enter passphrase for private key: ')
        passB = getpass.getpass('Enter passphrase for private key (again): ')
        if passA == passB:
            return passB
        else:
            print "Error: passwords don't match!"
            return "password_error"

    # Simple routines to load/save files using crypto lib
    # Save private key to file
    def save_key (self, fn, key):
        global keyPass
        # Adding passphrase to private key
        # do we need a random passphrase?
        if self.randpass:
            if self.debug: print "DEBUG: generating a random passphrase of %s characters" % self.randpass
            keyPass = ""
            for i in range(int(self.randpass)):
                keyPass += random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
            fp = open ( fn, 'w' )
            fp.write ( crypto.dump_privatekey ( self.FILETYPE, key, self.ciphermethod, keyPass ) )
            if self.debug: print "DEBUG: private key encrypted with RANDOM passphrase: '%s'" % keyPass
        elif self.passphrase:
            if self.passphrase == 'please_prompt_me':
                keyPass = self.getPass()
                if keyPass is "password_error":
                    # Don't write keyfile if supplied passwords mismatch
                    sys.exit()
                else:
                    fp = open ( fn, 'w' )
                    fp.write ( crypto.dump_privatekey ( self.FILETYPE, key, self.ciphermethod, keyPass ) )
                    if self.debug: print "DEBUG: private key encrypted with passphrase: '%s'" % keyPass
            else:
                fp = open ( fn, 'w' )
                fp.write ( crypto.dump_privatekey ( self.FILETYPE, key, self.ciphermethod, self.passphrase ) )
                if self.debug: print "DEBUG: private key encrypted with passphrase: '%s'" % self.passphrase
        else:
            fp = open ( fn, 'w' )
            fp.write ( crypto.dump_privatekey ( self.FILETYPE, key ) )
        fp.close ()

    # Save certificate to file
    def save_cert (self, fn, cert):
        fp = open ( fn, 'w' )
        fp.write ( crypto.dump_certificate ( self.FILETYPE, cert ) )
        fp.close ()

    # Load private key from file
    def load_key (self, fn):
        fp = open ( fn, 'r' )
        ret = crypto.load_privatekey ( self.FILETYPE, fp.read() )
        fp.close ()
        return ret

    # Load certificate from file
    def load_cert (self, fn):
        fp = open ( fn, 'r' )
        ret = crypto.load_certificate ( self.FILETYPE, fp.read() )
        fp.close ()
        return ret

    # Print information retreived from a certificate file
    def print_cert (self, cert):
        try:
            certfile = self.load_cert( cert )
        except:
            print "Error opening certificate file" 
            sys.exit()
        # Some objects are 'X509Name objects' so we have to fiddle a bit to output to a human-readable format
        certIssuerArray = str(certfile.get_issuer()).replace('<X509Name object \'', '').replace('\'>','').split('/')
        certIssuer = certIssuerArray[1] + ', ' + certIssuerArray[2] + ', ' + certIssuerArray[3] + ', ' + certIssuerArray[4]
        print "Issuer:\t\t" + str(certIssuer)
        certSubjectArray = str(certfile.get_subject()).replace('<X509Name object \'', '').replace('\'>','').split('/')
        certSubject = certSubjectArray[1] + ', ' + certSubjectArray[2] + ', ' + certSubjectArray[3] + ', ' + certSubjectArray[4]
        print "Subject:\t" + str(certSubject)
        print "Version:\t" + str(certfile.get_version())
        print "Serial number:\t" + str(certfile.get_serial_number())
        validFromYear = str(certfile.get_notBefore())[:4]
        validFromMonth = str(certfile.get_notBefore())[4:6]
        validFromDay = str(certfile.get_notBefore())[6:8]
        validFromTime = str(certfile.get_notBefore())[8:10] + ':' + str(certfile.get_notBefore())[10:12] + ':' + str(certfile.get_notBefore())[12:14]
        print "Valid from:\t" + validFromYear + '-' + validFromMonth + '-' + validFromDay + ' ' + validFromTime
        validUntilYear = str(certfile.get_notAfter())[:4]
        validUntilMonth = str(certfile.get_notAfter())[4:6]
        validUntilDay = str(certfile.get_notAfter())[6:8]
        validUntilTime = str(certfile.get_notAfter())[8:10] + ':' + str(certfile.get_notAfter())[10:12] + ':' + str(certfile.get_notAfter())[12:14]
        print "Valid until:\t" + validUntilYear + '-' + validUntilMonth + '-' + validUntilDay + ' ' + validUntilTime
        if str(certfile.has_expired()) == '1':
            print "Expired:\tyes"
        else:
            print "Expired:\tno"


    # Generate keyfile and certificate
    def makeCert(self, fname, cname):
        pkey = self.createKeyPair(self.TYPE_RSA, 1024)
        req = self.createCertRequest(pkey, CN=cname, C=countryName, ST=stateOrProvinceName, O=organizationName, OU=organizationalUnitName)
        try:
            cacert = self.load_cert( self.cacertfile )
        except:
            print "Error opening CA cert file"
            sys.exit()
        try:
            cakey = self.load_key(self.cakeyfile)
        except:
            print "Error opening CA key file"
            sys.exit()

        # check if the 'next serial number' in serialfile is the same as the serial number of the
        # last entry in the indexdb. If it is, increase the next serial by one (hex) and write a
        # new serialfile
        for line in open(indexdb):
            last=line
        last_serial = last.split("\t")[3].strip()
        if self.debug: print "Last serial in indexdb: '%s'" % last_serial
        f=open(serialfile, 'r')
        serial = f.readline().strip()
        f.close()
        if self.debug: print "Next serial in serialfile: '%s'" % serial
        if serial == last_serial:
            print "Whoops! Last serial number in indexdb is the same as the next"
            print "one in serialfile: %s. This is probably caused by an older version" % serial
            print "of StoneVPN. We'll need to correct this (once) by increasing"
            newSerialDec = self.hex2dec(serial) + 1
            newSerial = self.dec2hex(newSerialDec)
            print "the value for next serial number to %s" % newSerial
            if len(newSerial) == 1:
                newSerial = '0' + str(newSerial)
            if self.debug: print "Now increasing %s by 1 to %s" % (serial,newSerial)
            f=open(serialfile, 'w')
            f.write(newSerial)
            f.close()

        # read next serial number from serialfile
        curSerial = self.readSerial()

        # format current time as UTC, for certificate
        timeNow = datetime.utcnow()
        # format current time as local, for indexdb
        timeNowIdx = datetime.now()

        # We can't work with hex numbers. Convert them to dec first and increase its value by 1
        newSerial = self.hex2dec(curSerial) + 1
        newSerialDec = newSerial
        # Now convert dec back to hex 
        newSerial = self.dec2hex(newSerial)

        # Check if a different expiration date for certificate
        if self.expiredate:
            # Check for valid arguments: (h)ours, (d)ays, (y)ears.
            # For example: 2h or 6d or 2y. A combination is not (yet?) possible.
            expList = list(self.expiredate)
            try:
                unit = list(self.expiredate)[-1]
                if self.debug: print "DEBUG: time unit is %s" % unit
            except:
                print "Incorrect or missing time unit. Use h(ours), d(ays) or y(ears)."
                sys.exit()
            countRest = len(expList) - 1
            exp_time = ''.join(expList[0:countRest])
            if self.debug: print "DEBUG: exp_time is %s" % exp_time
            if unit not in ('h', 'H', 'd', 'D', 'y', 'Y'): 
                print "Invalid time unit provided. Use h(ours), d(ays) or y(ears)."
                sys.exit()
            elif unit in ('h', 'H'):
                cert = self.createCertificate(req, (cacert, cakey), curSerial, (0, 60 * 60 * int(exp_time)))
                expDate = timeNow + timedelta(hours=int(exp_time))
                expDateIdx = timeNowIdx + timedelta(hours=int(exp_time))
                print "Certificate is valid for %s hour(s)." % exp_time
            elif unit in ('d', 'D'):
                cert = self.createCertificate(req, (cacert, cakey), curSerial, (0, 24 * 60 * 60 * int(exp_time)))
                expDate = timeNow + timedelta(days=int(exp_time))
                expDateIdx = timeNowIdx + timedelta(days=int(exp_time))
                print "Certificate is valid for %s day(s)." % exp_time
            elif unit in ('y', 'Y'):
                cert = self.createCertificate(req, (cacert, cakey), curSerial, (0, 24 * 60 * 60 * 365 * int(exp_time)))
                expDate = timeNow + timedelta(days=int(exp_time) * 365)
                expDateIdx = timeNowIdx + timedelta(days=int(exp_time) * 365)
                print "Certificate is valid for %s year(s)." % exp_time
        else:
            cert = self.createCertificate(req, (cacert, cakey), curSerial, (0, 24 * 60 * 60 * int(defaultDays)))
            expDate = timeNow + timedelta(days=int(defaultDays))
            expDateIdx = timeNowIdx + timedelta(days=int(defaultDays))
            print "Certificate is valid for %s day(s)." % defaultDays
        self.save_key ( self.working + '/' + self.fprefix + fname + '.key', pkey )
        self.save_cert ( self.working + '/' + self.fprefix + fname + '.crt', cert )

        # OpenSSL only accepts serials of 2 digits, so check for the length and prepend a 0 if necessary
        if len(str(newSerial)) == 1:
            serialIdx = '0' + str(newSerial)
        else:
            serialIdx = newSerial
        # Write serial (hex) to serial file
        self.writeSerial(serialIdx)
        # copy CA certificate to working dir
        shutil.copy(self.cacertfile, self.working)
        # create the configuration files (default 'unix' unless specified with option -c)
        self.makeConfs(self.confs, fname)
        # write index to file
        if self.debug: print "DEBUG: timeNow is %s" % timeNow
        if self.debug: print "DEBUG: expDate is %s" % expDate
        # OpenSSL only accepts serials of 2 digits, so check for the length and prepend a 0 if necessary
        if len(str(curSerial)) == 1:
            serialNumber = '0' + str(curSerial)
        else:
            serialNumber = curSerial
        # convert cname: spaces to underscores for inclusion in indexdb
        nospaces_cname =  cname.replace(' ', '_')
        # the expire date for the index file needs some conversion
        indexDate = expDateIdx.strftime("%y%m%d%H%M%S")
        if self.debug: print "DEBUG: indexDate is %s" % indexDate
        # Format index line and write to OpenSSL index file
        index = 'V\t' + str(indexDate) + 'Z\t\t' + str(serialNumber.strip()) + '\tunknown\t' + '/C=' + str(countryName) + '/ST=' + str(stateOrProvinceName) + '/O=' + str(organizationName) + '/OU=' + str(organizationalUnitName) + '/CN=' + str(nospaces_cname) + '/emailAddress=' + str(fname) + '@local\n'
        self.writeIndex(index)

    # Make config files for OpenVPN
    def makeConfs(self, sname, fname):
        config = ConfigObj(self.stonevpnconf)
        # Generate appropriate (according to specified OS) configuration for OpenVPN
        if sname == 'unix' or sname == 'linux':
            sectionname = 'unix conf'
            print "Generating UNIX configuration file"
            f=open(self.working + '/' + self.fprefix + fname + '.conf', 'w')
        elif sname == 'windows':
            sectionname = 'windows conf'
            print "Generating Windows configuration file"
            f=open(self.working + '/' + self.fprefix + fname + '.ovpn', 'w')
        elif sname == 'mac':
            sectionname = 'mac conf'
            print "Generating Mac configuration file"
            f=open(self.working + '/' + self.fprefix + fname + '.conf', 'w')
        elif sname == 'all':
            print "Generating all configuration files"
        else:
            print "Incorrect OS type specified. Valid options are 'unix', 'windows', 'mac' or 'all'."
            sys.exit()
        if sname != 'all':
            section=config[sectionname]
            # Go over each entry (variable) and write it to the OpenVPN configuration file
            for var in section:
                # Fill in correct path to generated cert/key/cacert files
                if var == 'ca':
                    cacertfilenopath = self.cacertfile.split('/')[int(len(self.cacertfile.split('/')) - 1)]
                    f.write(section[var].replace('cacertfile', cacertfilenopath) + '\n')
                elif var == 'cert':
                    f.write(section[var].replace('clientcertfile', self.fprefix + fname + '.crt') + '\n')
                elif var == 'key':
                    f.write(section[var].replace('clientkeyfile', self.fprefix + fname + '.key') + '\n')
                elif var == 'ip':
                    if self.server_ip:
                        f.write("remote " + str(self.server_ip) + "\n")
                    else:
                        f.write(section[var] + '\n')
                else:
                    f.write(section[var] + '\n')
            f.close()
        else:
            os_versions = ["windows", "linux", "mac"]
            for os_type in os_versions:
                # soort extensie ipv deze regel <<
                if os_type == 'linux':
                    sectionname = 'unix conf'
                    print "Generating Linux configuration file"
                    f=open(self.working + '/' + self.fprefix + fname + '.linux.conf', 'w')
                elif os_type == 'windows':
                    sectionname = 'windows conf'
                    print "Generating Windows configuration file"
                    f=open(self.working + '/' + self.fprefix + fname + '.windows.ovpn', 'w')
                elif os_type == 'mac':
                    sectionname = 'mac conf'
                    print "Generating Mac configuration file"
                    f=open(self.working + '/' + self.fprefix + fname + '.mac.conf', 'w')
                section=config[sectionname]
                for var in section:
                    if var == 'ca':
                        cacertfilenopath = self.cacertfile.split('/')[int(len(self.cacertfile.split('/')) - 1)]
                        f.write(section[var].replace('cacertfile', cacertfilenopath) + '\n')
                    elif var == 'cert':
                        f.write(section[var].replace('clientcertfile', self.fprefix + fname + '.crt') + '\n')
                    elif var == 'key':
                        f.write(section[var].replace('clientkeyfile', self.fprefix + fname + '.key') + '\n')
                    else:
                        f.write(section[var] + '\n')
                f.close()


    # Revoke certificate
    def revokeCert(self, serial):
        if not os.path.exists(self.crlfile):
            print "Error: CRL file not found at: " + self.crlfile + " or insufficient rights."
            sys.exit()
	try:
        	crl = crypto.CRL()
	except:
		print "\nError: CRL support is not available in your version of"
		print "pyOpenSSL. Please check the README file that came with"
		print "StoneVPN to see what you can do about this. For now, "
		print "you will have to revoke certificates manually.\n"
   		sys.exit()
        # we can't replace stuff in the original index file, so we have to create
        # a new one and in the end rename the original one and move the temp file
        # to the final location (usually /etc/ssl/index.txt)
        t=open(self.working + '/index.tmp', 'w')
        # read SSL dbase from the index file
        # this file has 5 columns: Status, Expiry date, Revocation date, Serial nr, file?, Distinguished Name (DN)
        print "Reading SSL database: " + indexdb
        input = open(indexdb, 'r')
        f=open(self.working + '/revoked.crl', 'w')
        crlTime = str(strftime("%y%m%d%H%M%S")) + 'Z'
        for line in input:
            # first check if the line contains a revoked cert:
            if line.split()[0] == 'R':
                # then check if the revoked cert has the same serial nr as the one we're trying to revoke
                # if so, exit immediately since we can't revoke twice (duh)
                if line.split()[3] == serial:
                    print "Certificate with serial %s already revoked!" % serial
                    os.remove(self.working + '/index.tmp')
                    os.remove(self.working + '/revoked.crl')
                    sys.exit()
                else:
                    revSerial = str(line.split()[3])
                    revDate = str(line.split()[2])
                    revoked = crypto.Revoked()
                    revoked.set_rev_date('20' + str(revDate))
                    revoked.set_serial(revSerial)
                    #no reason needed?
                    #revoked.set_reason('revoked')
                    crl.add_revoked(revoked)
                    # /new way
                    print "Re-adding existing revoked certificate to CRL with date " + revDate + " and serial " + revSerial
                    t.write(line)
            else:
                # the line contains a valid certificate. Check if the serial is the same as the
                # one we're trying to revoke
                if line.split()[2] == serial:
                    # we have a match! do not write this line again to the new index file
                    # instead, change it to the revoked-format
                    newDN = '/'.join(line.split('/')[1:])
                    revokedLine = 'R\t' + str(line.split()[1]) + '\t' + crlTime + '\t' + serial + '\tunknown\t' + str(newDN)
                    t.write(revokedLine)
                else:
                    # this is not the match we're looking for, so just write the line again
                    # to the index file
                    t.write(line)
        # crlTime = str(strftime("%y%m%d%H%M%S")) + 'Z'
        print "Adding new revoked certificate to CRL with date " + crlTime + " and serial " + serial
        t.close()
        revoked = crypto.Revoked()
        now = datetime.utcnow().strftime("%Y%m%d%H%M%SZ")
        revoked.set_rev_date(now)
        revoked.set_serial(serial)
        #no reason needed?
        #revoked.set_reason('sUpErSeDEd')
        crl.add_revoked(revoked)
        cacert = self.load_cert(self.cacertfile)
        cakey = self.load_key(self.cakeyfile)
        newCRL = crl.export(cacert, cakey, days=20)
        f.write(newCRL)
        f.close()
        shutil.move(indexdb,indexdb + '.old')
        shutil.move(self.working + '/index.tmp',indexdb)
        shutil.move(self.crlfile,self.crlfile + '.old')
        shutil.move(self.working + '/revoked.crl',self.crlfile)
        print "New CRL written to: %s. Backup created as: %s." % (self.crlfile,self.crlfile + '.old')
        print "New index written to: %s. Backup created as: %s." % (indexdb,indexdb + '.old')

    def displayCRL(self):
        if not os.path.exists(self.crlfile):
            print "Error: CRL file not found at %s" % self.crlfile
            print "You can create one with: stonevpn --newcrl"
            sys.exit()
        text = open(self.crlfile, 'r').read()
        print "Parsing CRL file %s" % self.crlfile
        try:
        	crl = crypto.load_crl(crypto.FILETYPE_PEM, text)
        	revs = crl.get_revoked()
        except:
            print "\nError: CRL support is not available in your version of"
            print "pyOpenSSL. Please check the README file that came with"
            print "StoneVPN to see what you can do about this. For now, "
            print "you will have to display the CRL file manually using:\n"
            print "$ openssl crl -in %s -noout -text\n" % self.crlfile
            sys.exit()
        if not revs is None:
            print "Total certificates revoked: %s\n" % len(revs)
            print "Serial\tRevoked at date"
            print "======\t========================"
            for revoked in revs:
                revSerial = revoked.get_serial()
                revDate = revoked.get_rev_date()[0:-1]
                revoDate = time.strptime(revDate, "%Y%m%d%H%M%S")
                print str(revSerial) + "\t" + time.strftime("%c", revoDate)
        else:
            print "No revoked certificates found."


    def listRevokedCerts(self):
        # read SSL dbase (usually index.txt)
        # this file has 5 columns: Status, Expiry date, Revocation date, Serial nr, unknown, Distinguished Name (DN)
        print "Reading SSL database: " + indexdb
        input = open(indexdb, 'r')
        revCerts = []
        print "Finding revoked certificates..."
        for line in input:
            if line.split()[0] == 'R':
                revCerts.append(line)
        count = 0
        while count < len(revCerts):
            #print "Revoked certificate:\t" + str(revCerts[count].split()[5].split('/CN=')[1])
            print "Issued to:\t\t%s" % str(revCerts[count]).split('CN=')[1].split('/')[0]
            print "Status:\t\t\tRevoked"
            expDate = str(revCerts[count].split()[1])
            print "Expiry date:\t\t20%s-%s-%s %s:%s:%s" % (expDate[:2],expDate[2:4],expDate[4:6],expDate[6:8],expDate[8:10],expDate[10:12])
            revDate = str(revCerts[count].split()[2])
            print "Revocation date:\t20%s-%s-%s %s:%s:%s" % (revDate[:2],revDate[2:4],revDate[4:6],revDate[6:8],revDate[8:10],revDate[10:12]) 
            print "Serial:\t\t\t%s" % str(revCerts[count].split()[3])
            lineDN = line.split('unknown')[1].strip()
            newDN = ''.join(lineDN).replace('/',',')
            print "DN:\t\t\t%s" % newDN
            print "\n"
            count = count + 1

    def listAllCerts(self):
        print "Reading SSL database: " + indexdb
        # read SSL dbase (usually index.txt)
        # this file has 5 columns: Status, Expiry date, Revocation date, Serial nr, file?, Distinguished Name (DN)
        input = open(indexdb, 'r')
        print "Listing all issued certificates:\n"
        for line in input:
            if line.split()[0] == 'R':
                # Print revoked certificate
                issuee = line.split('/')[-2:][0].replace('CN=','').replace('_',' ')
                print "Issued to:\t\t" + str(issuee)
                print "Status:\t\t\tRevoked"
                revDate = str(line.split()[2]).replace('Z','')
                print "Revocation date:\t20%s-%s-%s %s:%s:%s" % (revDate[:2],revDate[2:4],revDate[4:6],revDate[6:8],revDate[8:10],revDate[10:12])
                print "Serial:\t\t\t" + str(line.split()[3])
                lineDN = line.split('unknown')[1].strip()
                newDN = ''.join(lineDN).replace('/',',')
                print "DN:\t\t\t" + str(newDN) + "\n"
            else:
                # Print valid certificate
                # everything starting with the first '/' until the end = issuee, replaced spaces with underlines
                issuee = line.split('/')[-2:-1][0].split('\t')[0].replace('CN=','').replace('_',' ')
                print "Issued to:\t\t" + issuee
                print "Status:\t\t\tValid"
                expDate = str(line.split()[1]).replace('Z','')
                print "Expiry date:\t\t20%s-%s-%s %s:%s:%s" % (expDate[:2],expDate[2:4],expDate[4:6],expDate[6:8],expDate[8:10],expDate[10:12])
                print "Serial:\t\t\t" + str(line.split()[2])
                lineDN = line.split('/')[-6:][0:]
                newDN = ','.join(lineDN)
                print "DN:\t\t\t" + str(newDN)
            #print "\n"


    def send_mail(self, send_from, send_to, subject, text, attachment=[]):
        print "Generating e-mail"
        msg = MIMEMultipart()
        msg['From'] = send_from
        msg['To'] = send_to
        msg['CC'] = self.mail_cc
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        text = text.replace('EMAILRECIPIENT', self.cname)
        # Append a helpful text when a password was given, but only when specified on the commandline
        if self.mailpass:
            if self.passphrase is None and self.randpass is None:
                print "Error: you need to specify either a passphrase or generate a random one."
                sys.exit()
            if keyPass:
                if self.debug: print "DEBUG: including password help text in email body"
                text = text.replace('PASSPHRASETXT', self.mail_passtxt)
                # And replace the password placeholder with the actual passphrase
                text = text.replace('OPENSSLPASS', keyPass)
        else:
            text = text.replace('PASSPHRASETXT', '')
        msg.attach( MIMEText(text, 'html') )
        # Attachment(s)
        if type(attachment) == 'string':
            part = MIMEBase('application', "octet-stream")
            part.set_payload( open(attachment,"rb").read() )
            Encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attachment))
            msg.attach(part)
        else:
            for f in attachment:
                print "Attaching file %s" % f
                part = MIMEBase('application', "octet-stream")
                part.set_payload( open(f,"rb").read() )
                Encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
                msg.attach(part)
        # Now to send the entire message
        print 'Sending e-mail with attachment(s) to %s' % self.emailaddress
        smtp = smtplib.SMTP(self.mail_server)
        smtp.sendmail(send_from, send_to, msg.as_string())
        smtp.close()
