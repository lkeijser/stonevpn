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

import os, sys, shutil, string
from OpenSSL import SSL, crypto
from optparse import OptionParser, OptionGroup
from configobj import ConfigObj


def main():
    stonevpnver = '0.4.7beta2'
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

    # retrieve default expiration date from openssl.cnf, needed for optionparse 
    config = ConfigObj(opensslconf)
    sectionname = 'CA_default'
    section=config[sectionname]
    defaultDays = section['default_days']

    # define some crypto stuff
    TYPE_RSA = crypto.TYPE_RSA
    TYPE_DSA = crypto.TYPE_DSA
    FILETYPE = crypto.FILETYPE_PEM

    # command line options
    parser = OptionParser(usage="%prog -f <filename> -n <commonname> [ OPTIONS ]",version="%prog " + stonevpnver)

    # define groups
    group_crl = OptionGroup(parser, "Certificate revocation options")
    group_general = OptionGroup(parser, "General options")
    group_extra = OptionGroup(parser, "Extra options")
    group_test = OptionGroup(parser, "Test/experimental options",
            "Caution: use these options with care.")

    # populate groups
    group_general.add_option("-n", "--name",
        action="store",
        type="string",
        dest="cname",
        help="Common Name, use quotes eg.: \"CNAME\"")
    group_general.add_option("-f", "--file",
        dest="fname",
        help="write to file FNAME (no extension!)")
    group_general.add_option("-o", "--config",
        action="store",
        dest="confs",
        default="unix",
        help="create config files for [windows|unix]")
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
        help="Send all generated files to EMAILADDRESS")
    group_test.add_option("-i", "--free-ip",
        action="store_true",
        dest="freeip", 
        help="locate and assign free ip (EXPERIMENTAL)")
    group_extra.add_option("-p", "--passphrase",
        action="store_true",
        dest="passphrase",
        help="prompt for passphrase when generating private key")
    group_crl.add_option("-r", "--revoke",
        action="store",
        dest="serial",
        help="revoke certificate with serial SERIAL")
    group_extra.add_option("-u", "--route",
        action="store",
        dest="route",
        help="Push extra route to client. Example: --route=172.16.0.0/16")
    group_crl.add_option("-l", "--listrevoked",
        action="store_true",
        dest="listrevoked",
        help="list revoked certificates")
    group_crl.add_option("-C", "--crl",
        action="store_true",
        dest="displaycrl",
        help="display CRL file contents")
    group_extra.add_option("-a", "--listall",
        action="store_true",
        dest="listall",
        help="list all certificates")
    group_extra.add_option("-s", "--showserial",
        action="store_true",
        dest="showserial",
        help="Display current SSL serial number")
    group_extra.add_option("-c", "--printcert",
        action="store",
        dest="printcert",
        help="Prints information about a certficiate file")
    group_extra.add_option("-d", "--printindex",
        action="store_true",
        dest="printindex",
        help="Prints index file")
    group_extra.add_option("-x", "--expire",
        action="store",
        dest="expiredate",
        help="certificate expires in EXPIREDATE days (default is defaultDays)")
    group_crl.add_option("-N", "--newcrl",
        action="store_true",
        dest="emptycrl",
        help="Create an empty CRL file (or overwrite an existing one)")
    group_test.add_option("-t", "--test",
        action="store_true",
        dest="test",
        help="Danger, Will Robinson, Danger! test parameter - can do anything! Review source before executing!")

    # add optiongroups
    parser.add_option_group(group_general)
    parser.add_option_group(group_extra)
    parser.add_option_group(group_crl)
    parser.add_option_group(group_test)

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
    s.displaycrl    = options.displaycrl
    s.listall       = options.listall
    s.showserial    = options.showserial
    s.printcert     = options.printcert
    s.printindex    = options.printindex
    s.expiredate    = options.expiredate
    s.emptycrl       = options.emptycrl
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
    if options.fname is None and options.serial is not None and options.listrevoked is not None and options.listall is not None and options.showserial is not None and options.printcert is not None and options.printindex is not None and options.emptycrl is not None and options.test is not None:
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
            try:
                range = IP(pool_from + '-' + pool_to)
            except ValueError:
                print "An error occured when trying to determine a valid"
                print "network prefix for your pool. Reverting to /25"
                print "If this is not desirable, please specify a valid"
                print "range in %s." % self.openvpnconf
                range = IP(pool_from).make_net('255.255.255.128')
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
                else:
                    pass
            else:
                print "Creating empty CRL file at %s" % self.crlfile
                cacert = self.load_cert(self.cacertfile)
                cakey = self.load_key(self.cakeyfile)
                newCRL = crl.export(cacert, cakey, days=90)
                f=open(self.crlfile, 'w')
                f.write(newCRL)
                f.close()



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
        	print "fix this by upgrading to at least pyOpenSSL 0.9."
        	print "==================================================================\n"
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
        # Adding passphrase to private key
        if self.passphrase:
            keyPass = self.getPass()
            if keyPass is "password_error":
                # Don't write keyfile if supplied passwords mismatch
                sys.exit()
            else:
                fp = open ( fn, 'w' )
                fp.write ( crypto.dump_privatekey ( self.FILETYPE, key, self.ciphermethod, keyPass ) )
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
        curSerial = self.readSerial()
        # We can't work with hex integers. Convert them to dec first
        newSerial = self.hex2dec(curSerial) + 1
        newSerialDec = newSerial
        # Now convert dec back to hex 
        newSerial = self.dec2hex(newSerial)
        # Check if a different expiration date for certificate
        if self.expiredate:
            cert = self.createCertificate(req, (cacert, cakey), newSerial, (0, 24 * 60 * 60 * int(self.expiredate)))
            print "Certificate is valid for %s day(s)." % self.expiredate
        else:
            cert = self.createCertificate(req, (cacert, cakey), newSerial, (0, 24 * 60 * 60 * int(defaultDays)))
            print "Certificate is valid for %s day(s)." % defaultDays
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
        index = 'V\t' + str(expDate) + 'Z\t' + str(serialNumber) + '\tunknown\t' + '/C=' + str(countryName) + '/ST=' + str(stateOrProvinceName) + '/O=' + str(organizationName) + '/OU=' + str(organizationalUnitName) + '/CN=' + str(nospaces_cname) + '/emailAddress=' + str(fname) + '@local\n'
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
	from datetime import datetime
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
                    print "Certificate already revoked!"
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
        now = datetime.now().strftime("%Y%m%d%H%M%SZ")
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
        import time
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


