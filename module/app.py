#!/usr/bin/env python
"""

 StoneVPN - Easy OpenVPN certificate and configuration management

 (C) 2009 by L.S. Keijser, <keijser@stone-it.com>

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

import os, sys, shutil
from OpenSSL import SSL, crypto
from optparse import OptionParser
from configobj import ConfigObj


def main():
    stonevpnver = '0.4.2'
    stonevpnconf = '/etc/stonevpn.conf'

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
    else:
        print "File " + stonevpnconf + " does not exist!"
        sys.exit()

    # define some crypto stuff
    TYPE_RSA = crypto.TYPE_RSA
    TYPE_DSA = crypto.TYPE_DSA
    FILETYPE = crypto.FILETYPE_PEM

    # command line options
    parser = OptionParser(usage="%prog -f <filename> -n <commonname> [ -o unix|windows | -z | -h | -i | -r <serial> | -l |-a ]",version="%prog " + stonevpnver)

    parser.add_option("-n", "--name",
        action="store",
        type="string",
        dest="cname",
        help="Common Name, use quotes: \"CNAME\"")
    parser.add_option("-f", "--file",
        dest="fname",
        help="write to file FNAME (no extension!)")
    parser.add_option("-o", "--config",
        action="store",
        dest="confs",
        default="unix",
        help="create config files for [windows|unix]")
    parser.add_option("-e", "--prefix",
        action="store",
        dest="fprefix",
        default=prefix,
        help="prefix (almost all) generated files. Default = " + str(prefix))
    parser.add_option("-z", "--zip",
        action="store_true",
        dest="zip",
        help="create ZIP-file and delete the rest")
    parser.add_option("-m", "--mail",
        action="store",
        type="string",
        dest="emailaddress",
        help="Send all generated files to EMAILADDRESS")
    parser.add_option("-i", "--free-ip",
        action="store_true",
        dest="freeip", 
        help="locate and assign free ip (EXPERIMENTAL)")
    parser.add_option("-p", "--passphrase",
        action="store_true",
        dest="passphrase",
        help="prompt for passphrase when generating private key")
    parser.add_option("-r", "--revoke",
        action="store",
        dest="serial",
        help="revoke certificate with serial SERIAL")
    parser.add_option("-u", "--route",
        action="store",
        dest="route",
        help="Push extra route to client. Example: --route=172.16.0.0/16")
    parser.add_option("-l", "--listrevoked",
        action="store_true",
        dest="listrevoked",
        help="list revoked certificates")
    parser.add_option("-a", "--listall",
        action="store_true",
        dest="listall",
        help="list all certificates")
    parser.add_option("-s", "--showserial",
        action="store_true",
        dest="showserial",
        help="Display current SSL serial number")
    parser.add_option("-c", "--printcert",
        action="store",
        dest="printcert",
        help="Prints information about a certficiate file")
    parser.add_option("-d", "--printindex",
        action="store_true",
        dest="printindex",
        help="Prints index file")
    parser.add_option("-t", "--test",
        action="store_true",
        dest="test",
        help="Danger, Will Robinson, Danger! test parameter - can do anything! Review source before executing!")

    # parse cmd line options
    (options, args) = parser.parse_args()

    s = StoneVPN()
    # values we got from optparse:
    s.cname         = options.cname
    s.fname         = options.fname
    s.confs         = options.confs
    s.fprefix       = options.fprefix
    s.zip           = options.zip
    s.emailaddress  = options.emailaddress
    s.freeip        = options.freeip
    s.passphrase    = options.passphrase
    s.serial        = options.serial
    s.route         = options.route
    s.listrevoked   = options.listrevoked
    s.listall       = options.listall
    s.showserial    = options.showserial
    s.printcert     = options.printcert
    s.printindex    = options.printindex
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
    s.stonevpnconf  = stonevpnconf
    # and all other variables
    s.TYPE_RSA      = TYPE_RSA
    s.TYPE_DSA      = TYPE_DSA
    s.FILETYPE      = FILETYPE
    s.stonevpnver   = stonevpnver

    # check for all args
    if options.fname is None:
        parser.error("Error: you have to specify a filename (FNAME)")
    else:
        # must..have..root..
        import commands
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
        self.serial        = None
        self.route         = None
        self.listrevoked   = None
        self.listall       = None
        self.showserial    = None
        self.printcert     = None
        self.printindex    = None
        self.test          = None
        # should we do the same for values we got from
        # parsing the configuration file? i don't think
        # so, so let's comment them out for now.
        #self.cacertfile    = None
        #self.cakeyfile     = None
        #self.openvpnconf   = None
        #self.stonevpnconf  = None
        #self.ccddir        = None
        #self.working       = None
        #self.opensslconf   = None
        #self.pushrouter    = None
        #self.ciphermethod  = None
        #self.prefix        = None
        #self.crlfile       = None
        #self.mail_server   = None
        #self.mail_cc       = None
        #self.mail_msg      = None
        #self.mail_from     = None

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
        except KeyError:
            print "KeyError: missing section 'countryName_default' in " + self.opensslconf
            sys.exit()
        try:
            stateOrProvinceName = section['stateOrProvinceName_default']
        except KeyError:
            print "KeyError: missing section 'stateOrProvinceName_default' in " + self.opensslconf
            sys.exit()
        try:
            localityName = section['localityName_default']
        except KeyError:
            print "KeyError: missing section 'localityName_default' in " + self.opensslconf
            sys.exit()
        try:
            organizationName = section['0.organizationName_default']
        except KeyError:
            print "KeyError: missing section '0.organizationName_default' in " + self.opensslconf
            sys.exit()
        try:
            organizationalUnitName = section['organizationalUnitName_default']
        except KeyError:
            print "KeyError: missing section 'organizationalUnitName_default' in " + self.opensslconf
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

        # Commented out check for 'fname' since we do that in main()
        #def checkFileOption():
        #    if not options.fname:
        #        print "Error: no filename specified! Try " + sys.argv[0] + " --help"
        #        sys.exit()

        # Make sure FPREFIX ends with a dash
        if not self.fprefix[-1] == '-':
            self.fprefix = str(self.fprefix) + '-'

        
        # check if working dir exists, create it if it doesn't
        if not os.path.exists(self.working):
            print "Working dir didn't exist, making ..."
            os.mkdir(self.working)
        # Make certificates
        if self.cname: 
            print "Creating " + self.fname + ".key and " + self.fname + ".crt for " + self.cname
            self.makeCert( self.fname, self.cname )

        # Make nice zipfile from all the generated files
        # :: called only when option '-z' is used ::
        if self.zip:
            import zipfile
            import glob
            print "Adding all files to " + self.fprefix + self.fname + ".zip"
            z = zipfile.ZipFile(self.working + "/" + self.fprefix + self.fname + ".zip", "w")
            for name in glob.glob(self.working + "/" + self.fprefix + self.fname + ".*"):
                # only add the files that begin with the name specified with the -f option, don't add the zipfile itself (duh)
                if not name == self.working + "/" + self.fprefix + self.fname + ".zip": z.write(name, os.path.basename(name), zipfile.ZIP_DEFLATED)
            # and add the CA certificate file
            z.write(self.cacertfile, os.path.basename(self.cacertfile), zipfile.ZIP_DEFLATED)
            z.close()
            # delete all the files generated, except the ZIP-file
            for file in glob.glob(self.working + "/" + self.fprefix + self.fname + ".*"):
                if not file == self.working + "/" + self.fprefix + self.fname + ".zip": os.remove(file)

        # Find free IP-address by parsing config files (usually in /etc/openvpn/ccd/*)
        # :: called only when option '-i' is used ::
        if self.freeip:
            print "Searching for free IP-address:"
            # since we're writing to the ccd dir, check if we have root privileges
            gotRoot()
            import glob, fileinput, string
            # parse config file in search for ifconfig-pool
            for line in fileinput.input(self.openvpnconf):
                if line.split()[0] == 'ifconfig-pool':
                    pool_from = line.split()[1]
                    pool_to = line.split()[2]
                    print "Pool runs from " + pool_from + " to " + pool_to
            import IPy
            IPy.check_addr_prefixlen = False    # set so that IP-addresses other than x.x.x.0/x can be handled
            from IPy import IP
            range = IP(pool_from + '-' + pool_to)
            # define list of IP-addresses
            ipList = []
            for x in range:
                ipList.append(x)
            # go through the individual config files to find IP-addresses
            for file in glob.glob(self.ccddir+"/*"):
                print "Parsing file: " + file
                for line in fileinput.input(file):
                    # search for line that starts with 'ifconfig-push'
                    if line.split()[0] == 'ifconfig-push':
                        # the client IP is the 2nd argument ([2] is 0,1,2nd object on the line)
                        clientip = line.split()[2]
                        # remove IP from range if it exists in the list
                        if IP(clientip) in ipList:
                            ipList.remove(IP(clientip)) 
                        # the server IP is the 1st argument
                        servip = line.split()[1]
                        # remove IP from range if it exists in the list
                        if IP(servip) in ipList:
                            ipList.remove(IP(servip))
            # sort list
            ipList.sort()
            # we now have a list of usable IP addresses :)
            # find 2 free IP-addresses:
            firstFree = ipList[0]
            secondFree = ipList[1]
            print "First free address: " + str(firstFree)
            print "Second free address: " + str(secondFree)
            # check if ccd dir exists:
            if not os.path.exists(self.ccddir):
                print "Client configuration directory didn't exist, making ..."
                os.mkdir(self.ccddir)
            # And create the configuration file for these addresses
            f=open(self.ccddir + '/' + self.fname, 'w')
            f.write('ifconfig-push ' + str(firstFree) + ' ' + str(secondFree) + '\n')
            f.write('push "route ' + self.pushrouter + ' 255.255.255.255"\n')
            f.close()
            print "CCD file written to: " + self.ccddir + '/' + self.fname

        if self.listall:
            self.listAllCerts()

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
            mail_attachment = []
            mail_to = self.emailaddress
            # First check if we've generated a ZIP file (include just one attachment) or not (include all generated files)
            if self.zip:
                mail_attachment.append(self.working + '/' + self.fprefix + self.fname + '.zip')
                self.send_mail(self.mail_from, mail_to, 'StoneVPN: generated files for ' + str(self.cname), self.mail_msg, mail_attachment)
            else:
                # Generate a list of filenames to include as attachments
                import glob
                for name in glob.glob(self.working + "/" + self.fprefix + self.fname + ".*"):
                    mail_attachment.append(name)
                # Also include the CA certificate
                mail_attachment.append(self.cacertfile)
                self.send_mail(self.mail_from, mail_to, 'StoneVPN: generated files for ' + str(self.cname), self.mail_msg, mail_attachment)

        if self.route:
            from IPy import IP
            ip=IP(self.route).strNormal(2)
            route = str(ip).split('/')
            nospaces_cname =  self.cname.replace(' ', '_')
            # check if ccd dir exists:
            if not os.path.exists(self.ccddir):
                print "Client configuration directory didn't exist, making ..."
                os.mkdir(self.ccddir)
            f=open(self.ccddir + '/' + nospaces_cname, 'w')
            f.write("push route \"" + route[0] + " " + route[1] + "\"\n")
            f.close()
            print "Wrote extra route(s) to " + self.ccddir + "/" + nospaces_cname

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
        extensions.append(crypto.X509Extension('nsComment',0, 'Created with stonevpn ' + str(self.stonevpnver)))
        # We're creating a X509 certificate version 2
        cert = crypto.X509()
        cert.set_version ( 2 )
        # Add the Extension to the certificate
        cert.add_extensions(extensions)
        # Create a valid hexidecimal serial number
        from string import atoi
        goodserial = atoi(str(serial), 16)
        cert.set_serial_number(goodserial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(issuerKey, digest)
        return cert

    # Passphrase
    def getPass(self):
        import getpass
        return getpass.getpass('Enter passphrase for private key: ')

    # Simple routines to load/save files using crypto lib
    # Save private key to file
    def save_key (self, fn, key):
        fp = open ( fn, 'w' )
        # Adding passphrase to private key
        if self.passphrase:
            fp.write ( crypto.dump_privatekey ( self.FILETYPE, key, self.ciphermethod, self.getPass() ) )
        else:
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
        curSerial = self.readSerial()
        # We can't work with hex integers. Convert them to dec first
        newSerial = self.hex2dec(curSerial) + 1
        newSerialDec = newSerial
        # Now convert dec back to hex 
        newSerial = self.dec2hex(newSerial)
        cert = self.createCertificate(req, (cacert, cakey), newSerialDec, (0, 24 * 60 * 60 * int(defaultDays)))
        self.save_key ( self.working + '/' + self.fprefix + fname + '.key', pkey )
        self.save_cert ( self.working + '/' + self.fprefix + fname + '.crt', cert )
        # Write serial (hex) to serial file
        self.writeSerial(newSerial)
        # copy CA certificate to working dir
        shutil.copy(self.cacertfile, self.working)
        # create the configuration files (default 'unix' unless specified with option -c)
        self.makeConfs(self.confs, fname)
        # write index to file
        from time import strftime
        curYear = str(strftime("%y"))
        newYear = int(curYear) + 1
        expDate = str(newYear) + str(strftime("%m%d%H%M%S"))
        # OpenSSL only accepts serials of 2 digits, so check for the length and prepend a 0 if necessary
        if len(str(newSerial)) == 1:
            serialNumber = '0' + str(newSerial)
        else:
            serialNumber = newSerial
        # convert cname: spaces to underscores for inclusion in indexdb
        nospaces_cname =  cname.replace(' ', '_')
        # Format index line and write to OpenSSL index file
        index = 'V\t' + str(expDate) + 'Z\t' + str(serialNumber) + '\tunknown\t' + '/C=' + str(countryName) + '/ST=' + str(stateOrProvinceName) + '/O=' + str(organizationName) + '/OU=' + str(organizationalUnitName) + '/CN=' + str(nospaces_cname) + '\tUser/emailAddress=' + str(fname) + '@local\n'
        self.writeIndex(index)

    # Make config files for OpenVPN
    def makeConfs(self, sname, fname):
        import string
        config = ConfigObj(self.stonevpnconf)
        # Generate appropriate (according to specified OS) configuration for OpenVPN
        if sname == 'unix':
            sectionname = 'unix conf'
            print "Generating UNIX configuration file"
            f=open(self.working + '/' + self.fprefix + fname + '.conf', 'w')
        elif sname == 'windows':
            sectionname = 'windows conf'
            print "Generating Windows configuration file"
            f=open(self.working + '/' + self.fprefix + fname + '.ovpn', 'w')
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
            else:
                f.write(section[var] + '\n')
        f.close()

    # Revoke certificate
    def revokeCert(self, serial):
        if not os.path.exists(self.crlfile):
            print "Error: CRL file not found at: " + self.crlfile + " or insufficient rights."
            sys.exit()
        from time import strftime
        crl = crypto.CRL()

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
                    print "Certificate already revoked!"
                    os.remove(self.working + '/index.tmp')
                    os.remove(self.working + '/revoked.crl')
                    sys.exit()
                else:
                    revSerial = str(line.split()[3])
                    revDate = str(line.split()[2])
                    crl.make_revoked(revDate, revSerial)
                    print "Adding to CRL with date " + revDate + " and serial " + revSerial
                    t.write(line)
            # the line contains a valid certificate. Check if the serial is the same as the
            # one we're trying to revoke
            else:
                if line.split()[2] == serial:
                    # we have a match! do not write this line again to the new index file
                    # instead, change it to the revoked-format
                    t.write('R\t' + str(line.split()[1]) + '\t' + crlTime + '\t' + serial + '\tunknown\t' + str(line.split()[4]) + '\n')
                else:
            # this is not the match we're looking for, so just write the line again
            # to the index file
                    t.write(line)
        # crlTime = str(strftime("%y%m%d%H%M%S")) + 'Z'
        print "adding new revoked certificate to CRL with date " + crlTime + " and serial " + serial
        crl.make_revoked(crlTime, serial)
        cacert = self.load_cert(self.cacertfile)
        cakey = self.load_key(self.cakeyfile)
        newCRL = crypto.dump_crl(crl, cacert, cakey)
        f.write(newCRL)
        f.close()
        shutil.move(indexdb,indexdb + '.old')
        shutil.move(self.working + '/index.tmp',indexdb)
        shutil.move(self.crlfile,self.crlfile + '.old')
        shutil.move(self.working + '/revoked.crl',self.crlfile)
        print "New CRL written to: " + self.crlfile
        print "Old CRL renamed to: " + self.crlfile + '.old'
        print "New index written to: " + indexdb
        print "Old index renamed to: " + indexdb + '.old'

    def listRevokedCerts(self):
        # read SSL dbase (usually index.txt)
        # this file has 5 columns: Status, Expiry date, Revocation date, Serial nr, file?, Distinguished Name (DN)
        print "Reading SSL database: " + indexdb
        input = open(indexdb, 'r')
        revCerts = []
        print "Finding revoked certificates..."
        for line in input:
            if line.split()[0] == 'R':
                revCerts.append(line)
        count = 0
        while count < len(revCerts):
            print "Revoked certificate:\t" + str(revCerts[count].split()[5].split('/CN=')[1])
            print "Status:\t\t\t" + str(revCerts[count].split()[0])
            print "Expiry date:\t\t" + str(revCerts[count].split()[1])
            print "Revocation date:\t" + str(revCerts[count].split()[2])
            print "Serial:\t\t\t" + str(revCerts[count].split()[3])
            print "DN:\t\t\t" + str(revCerts[count].split()[5])
            print "\n"
            count = count + 1

    def listAllCerts(self):
        print "Reading SSL database: " + indexdb
        # read SSL dbase (usually index.txt)
        # this file has 5 columns: Status, Expiry date, Revocation date, Serial nr, file?, Distinguished Name (DN)
        input = open(indexdb, 'r')
        print "Listing all issued certificates..."
        for line in input:
            if line.split()[0] == 'R':
                print "Certificate:\t\t" + str(line.split()[5].split('/CN=')[1])
                print "Status:\t\t\tRevoked"
                print "Expiry date:\t\t" + str(line.split()[1])
                print "Revocation date:\t" + str(line.split()[2])
                print "Serial:\t\t\t" + str(line.split()[3])
                print "DN:\t\t\t" + str(line.split()[5])
            else:
                print "Certificate:\t\t" + str(line.split()[4].split('/CN=')[1])
                print "Status:\t\t\tValid"
                print "Expiry date:\t\t" + str(line.split()[1])
                print "Serial:\t\t\t" + str(line.split()[2])
            print "DN:\t\t\t" + str(line.split()[4])
            print "\n"


    def send_mail(self, send_from, send_to, subject, text, attachment=[]):
        import smtplib
        import os
        from email.MIMEMultipart import MIMEMultipart
        from email.MIMEBase import MIMEBase
        from email.MIMEText import MIMEText
        from email.Utils import formatdate
        from email import Encoders
        print "Generating e-mail"
        msg = MIMEMultipart()
        msg['From'] = send_from
        msg['To'] = send_to
        msg['CC'] = self.mail_cc
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        text = text.replace('EMAILRECIPIENT', self.cname)
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


