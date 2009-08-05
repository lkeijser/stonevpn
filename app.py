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

stonevpnver = '0.4.1'
stonevpnconf = '/etc/stonevpn.conf'

# must..have..root..
def gotRoot():
    import commands
    myId = commands.getstatusoutput('id -u')[1]
    if not myId == '0':
        print "Sorry, "+color('red')+"root"+color('0')+" privileges required for this action."
        sys.exit(0)

# Read main configuration from stonevpn.conf
def readMainConf():
    config = ConfigObj(stonevpnconf)
    sectionname = 'stonevpn conf'
    section=config[sectionname]
    # Define global variables (can be called from anywhere in the program)
    global cacertfile, cakeyfile, openvpnconf, ccddir, working, opensslconf, pushrouter, ciphermethod, prefix, crlfile, mail_server, mail_cc, mail_msg, mail_from
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


# Make things pretty with colors
def color(code):
    if code == 'red': return '\033[1;31m'
    if code == 'green': return '\033[1;32'
    if code == 'yellow': return '\033[1;33'
    if code == 'blue': return '\033[1;34'
    if code == '0': return '\033[0m'

# Read certain vars from OpenSSL config file
def readOpenSSLConf():
    config = ConfigObj(opensslconf)
    sectionname = 'req_distinguished_name'
    section=config[sectionname]
    # make these variables also global
    global countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitName, defaultDays, prefixdir, indexdb, serialfile
    # Check if certain sections in OpenSSL configfile are present, report if they're not
    try:
        countryName = section['countryName_default']
    except KeyError:
        print "KeyError: missing section 'countryName_default' in " + opensslconf
        sys.exit()
    try:
        stateOrProvinceName = section['stateOrProvinceName_default']
    except KeyError:
        print "KeyError: missing section 'stateOrProvinceName_default' in " + opensslconf
        sys.exit()
    try:
        localityName = section['localityName_default']
    except KeyError:
        print "KeyError: missing section 'localityName_default' in " + opensslconf
        sys.exit()
    try:
        organizationName = section['0.organizationName_default']
    except KeyError:
        print "KeyError: missing section '0.organizationName_default' in " + opensslconf
        sys.exit()
    try:
        organizationalUnitName = section['organizationalUnitName_default']
    except KeyError:
        print "KeyError: missing section 'organizationalUnitName_default' in " + opensslconf
        sys.exit()
    sectionname = 'CA_default'
    section=config[sectionname]
    defaultDays = section['default_days']
    prefixdir = section['dir']
    indexdb = section['database'].replace('$dir', prefixdir)
    serialfile = section['serial'].replace('$dir', prefixdir)

if os.path.exists(stonevpnconf):
    readMainConf()
else:
    print "File " + stonevpnconf + " does not exist!"
    sys.exit()

if os.path.exists(opensslconf):
    readOpenSSLConf()
else:
    print "File " + opensslconf + " does not exist!"
    sys.exit()

# Check for presence of OpenSSL index file
if not os.path.exists(indexdb):
    print "Error: indexfile not found at: " + indexdb + " or insufficient rights."
    sys.exit()

# Check for presence of OpenSSL serial file
if not os.path.exists(serialfile):
    print "Error: serialfile not found at: " + serialfile + " or insufficient rights."
    sys.exit()

# command line options
parser = OptionParser(usage="%prog -f <filename> -n <commonname> [ -o unix|windows | -z | -h | -i | -r <serial> | -l |-a ]",version="%prog " + stonevpnver)

# how to add more options:
# syntax: parser.add_options("-option", "--longoption",
#             action="store", type="string", dest="<variable>", default="<default for var>", help="<help text>")
# use action="store_true" if the option doesn't require an argument
parser.add_option("-n", "--name",
    action="store", type="string", dest="cname", help="Common Name, use quotes: \"CNAME\"")
parser.add_option("-f", "--file",
    dest="fname", help="write to file FNAME (no extension!)")
parser.add_option("-o", "--config",
    action="store", dest="confs", default="unix", help="create config files for [windows|unix]")
parser.add_option("-e", "--prefix",
    action="store", dest="fprefix", default=prefix, help="prefix (almost all) generated files. Default = " + str(prefix))
parser.add_option("-z", "--zip",
    action="store_true", dest="zip", help="create ZIP-file and delete the rest")
parser.add_option("-m", "--mail",
    action="store", type="string", dest="emailaddress", help="Send all generated files to EMAILADDRESS")
parser.add_option("-i", "--free-ip",
    action="store_true", dest="freeip", help="locate and assign free ip (EXPERIMENTAL)")
parser.add_option("-p", "--passphrase",
    action="store_true", dest="passphrase", help="prompt for passphrase when generating private key")
parser.add_option("-r", "--revoke",
    action="store", dest="serial", help="revoke certificate with serial SERIAL")
parser.add_option("-u", "--route",
        action="store", dest="route", help="Push extra route to client. Example: --route=172.16.0.0/16")
parser.add_option("-l", "--listrevoked",
    action="store_true", dest="listrevoked", help="list revoked certificates")
parser.add_option("-a", "--listall",
    action="store_true", dest="listall", help="list all certificates")
parser.add_option("-s", "--showserial",
    action="store_true", dest="showserial", help="Display current SSL serial number from " + serialfile )
parser.add_option("-c", "--printcert",
    action="store", dest="printcert", help="Prints information about a certficiate file")
parser.add_option("-d", "--printindex",
    action="store_true", dest="printindex", help="Prints index file " + indexdb )
parser.add_option("-t", "--test",
    action="store_true", dest="test", help="Danger, Will Robinson, Danger! test parameter - can do anything! Review source before executing!")

# parse cmd line options
(options, args) = parser.parse_args()

def checkFileOption():
    if not options.fname:
        print color('red')+"Error"+color('0')+": no filename specified! Try " + sys.argv[0] + " --help"
        sys.exit()

# Make sure FPREFIX ends with a dash
if not options.fprefix[-1] == '-':
	options.fprefix = str(options.fprefix) + '-'

# define some crypto stuff
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
FILETYPE = crypto.FILETYPE_PEM

# check if working dir exists, create it if it doesn't
if not os.path.exists(working):
    print "Working dir didn't exist, making ..."
    os.mkdir(working)

# Create key
def createKeyPair(type, bits):
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

# Create request
def createCertRequest(pkey, digest="md5", **name):
    req = crypto.X509Req()
    subj = req.get_subject()
    for (key,value) in name.items():
        setattr(subj, key, value)
    req.set_pubkey(pkey)
    req.sign(pkey, 'md5')
    return req

# decimal 2 hexidecimal and vice versa
def dec2hex(n):
    return "%X" % n

def hex2dec(s):
    return int(s, 16)

def printIndexDB():
    f=open(indexdb, 'r')
    for line in f:
	print line
    f.close()

def readSerial():
    f=open(serialfile, 'r')
    serial = f.readline()
    f.close()
    return serial

def writeSerial(serial):
    f=open(serialfile, 'w')
    f.write(serial)
    f.close()

def writeIndex(index):
    f=open(indexdb, 'a')
    f.write(index)
    f.close()

# Create certificate
def createCertificate(req, (issuerCert, issuerKey), serial, (notBefore, notAfter), digest="md5"):
    extensions = []
    # Create the X509 Extensions
    extensions.append(crypto.X509Extension('basicConstraints',1, 'CA:FALSE'))
    extensions.append(crypto.X509Extension('nsComment',0, 'Created with stonevpn ' + str(stonevpnver)))
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
def getPass():
    import getpass
    return getpass.getpass('Enter passphrase for private key: ')

# Simple routines to load/save files using crypto lib
# Save private key to file
def save_key ( fn, key ):
    fp = open ( fn, 'w' )
    # Adding passphrase to private key
    if options.passphrase:
        fp.write ( crypto.dump_privatekey ( FILETYPE, key, ciphermethod, getPass() ) )
    else:
        fp.write ( crypto.dump_privatekey ( FILETYPE, key ) )
    fp.close ()

# Save certificate to file
def save_cert ( fn, cert ):
    fp = open ( fn, 'w' )
    fp.write ( crypto.dump_certificate ( FILETYPE, cert ) )
    fp.close ()

# Load private key from file
def load_key ( fn ):
    fp = open ( fn, 'r' )
    ret = crypto.load_privatekey ( FILETYPE, fp.read() )
    fp.close ()
    return ret

# Load certificate from file
def load_cert ( fn ):
    fp = open ( fn, 'r' )
    ret = crypto.load_certificate ( FILETYPE, fp.read() )
    fp.close ()
    return ret

# Print information retreived from a certificate file
def print_cert ( cert ):
    try:
        certfile = load_cert( cert )
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
def makeCert(fname, cname):
    pkey = createKeyPair(TYPE_RSA, 1024)
    req = createCertRequest(pkey, CN=cname, C=countryName, ST=stateOrProvinceName, O=organizationName, OU=organizationalUnitName)
    try:
        cacert = load_cert( cacertfile )
    except:
        print "Error opening CA cert file"
        sys.exit()
    try:
        cakey = load_key( cakeyfile )
    except:
        print "Error opening CA key file"
        sys.exit()
    curSerial = readSerial()
    # We can't work with hex integers. Convert them to dec first
    newSerial = hex2dec(curSerial) + 1
    newSerialDec = newSerial
    # Now convert dec back to hex 
    newSerial = dec2hex(newSerial)
    cert = createCertificate(req, (cacert, cakey), newSerialDec, (0, 24 * 60 * 60 * int(defaultDays)))
    save_key ( working + '/' + options.fprefix + fname + '.key', pkey )
    save_cert ( working + '/' + options.fprefix + fname + '.crt', cert )
    # Write serial (hex) to serial file
    writeSerial(newSerial)
    # copy CA certificate to working dir
    shutil.copy(cacertfile, working)
    # create the configuration files (default 'unix' unless specified with option -c)
    makeConfs(options.confs, fname)
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
    writeIndex(index)

# Make config files for OpenVPN
def makeConfs(sname, fname):
    import string
    config = ConfigObj(stonevpnconf)
    # Generate appropriate (according to specified OS) configuration for OpenVPN
    if sname == 'unix':
        sectionname = 'unix conf'
        print "Generating UNIX configuration file"
        f=open(working + '/' + options.fprefix + fname + '.conf', 'w')
    elif sname == 'windows':
        sectionname = 'windows conf'
        print "Generating Windows configuration file"
        f=open(working + '/' + options.fprefix + fname + '.ovpn', 'w')
    section=config[sectionname]
    # Go over each entry (variable) and write it to the OpenVPN configuration file
    for var in section:
        # Fill in correct path to generated cert/key/cacert files
        if var == 'ca':
            cacertfilenopath = cacertfile.split('/')[int(len(cacertfile.split('/')) - 1)]
            f.write(section[var].replace('cacertfile', cacertfilenopath) + '\n')
        elif var == 'cert':
            f.write(section[var].replace('clientcertfile', options.fprefix + fname + '.crt') + '\n')
        elif var == 'key':
            f.write(section[var].replace('clientkeyfile', options.fprefix + fname + '.key') + '\n')
        else:
            f.write(section[var] + '\n')
    f.close()

# Make certificates
if options.cname: 
    checkFileOption()
    print "Creating " + options.fname + ".key and " + options.fname + ".crt for " + options.cname
    makeCert( options.fname, options.cname )

# Make nice zipfile from all the generated files
# :: called only when option '-z' is used ::
if options.zip:
    checkFileOption()
    import zipfile
    import glob
    print "Adding all files to " + options.fprefix + options.fname + ".zip"
    z = zipfile.ZipFile(working + "/" + options.fprefix + options.fname + ".zip", "w")
    for name in glob.glob(working + "/" + options.fprefix + options.fname + ".*"):
        # only add the files that begin with the name specified with the -f option, don't add the zipfile itself (duh)
        if not name == working + "/" + options.fprefix + options.fname + ".zip": z.write(name, os.path.basename(name), zipfile.ZIP_DEFLATED)
    # and add the CA certificate file
    z.write(cacertfile, os.path.basename(cacertfile), zipfile.ZIP_DEFLATED)
    z.close()
    # delete all the files generated, except the ZIP-file
    for file in glob.glob(working + "/" + options.fprefix + options.fname + ".*"):
        if not file == working + "/" + options.fprefix + options.fname + ".zip": os.remove(file)

# Find free IP-address by parsing config files (usually in /etc/openvpn/ccd/*)
# :: called only when option '-i' is used ::
if options.freeip:
    checkFileOption()
    print "Searching for free IP-address:"
    # since we're writing to the ccd dir, check if we have root privileges
    gotRoot()
    import glob, fileinput, string
    # parse config file in search for ifconfig-pool
    for line in fileinput.input(openvpnconf):
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
    for file in glob.glob(ccddir+"/*"):
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
    if not os.path.exists(ccddir):
        print "Client configuration directory didn't exist, making ..."
        os.mkdir(ccddir)
    # And create the configuration file for these addresses
    f=open(ccddir + '/' + options.fname, 'w')
    f.write('ifconfig-push ' + str(firstFree) + ' ' + str(secondFree) + '\n')
    f.write('push "route ' + pushrouter + ' 255.255.255.255"\n')
    f.close()
    print "CCD file written to: " + ccddir + '/' + options.fname

# Revoke certificate
def revokeCert(serial):
    if not os.path.exists(crlfile):
        print "Error: CRL file not found at: " + crlfile + " or insufficient rights."
        sys.exit()
    from time import strftime
    crl = crypto.CRL()

    # we can't replace stuff in the original index file, so we have to create
    # a new one and in the end rename the original one and move the temp file
    # to the final location (usually /etc/ssl/index.txt)
    t=open(working + '/index.tmp', 'w')
    # read SSL dbase from the index file
    # this file has 5 columns: Status, Expiry date, Revocation date, Serial nr, file?, Distinguished Name (DN)
    print "Reading SSL database: " + indexdb
    input = open(indexdb, 'r')
    f=open(working + '/revoked.crl', 'w')
    crlTime = str(strftime("%y%m%d%H%M%S")) + 'Z'
    for line in input:
        # first check if the line contains a revoked cert:
        if line.split()[0] == 'R':
            # then check if the revoked cert has the same serial nr as the one we're trying to revoke
            # if so, exit immediately since we can't revoke twice (duh)
            if line.split()[3] == serial:
                print "Certificate already revoked!"
                os.remove(working + '/index.tmp')
                os.remove(working + '/revoked.crl')
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
    cacert = load_cert( cacertfile )
    cakey = load_key( cakeyfile )
    newCRL = crypto.dump_crl(crl, cacert, cakey)
    f.write(newCRL)
    f.close()
    shutil.move(indexdb,indexdb + '.old')
    shutil.move(working + '/index.tmp',indexdb)
    shutil.move(crlfile,crlfile + '.old')
    shutil.move(working + '/revoked.crl',crlfile)
    print "New CRL written to: " + crlfile
    print "Old CRL renamed to: " + crlfile + '.old'
    print "New index written to: " + indexdb
    print "Old index renamed to: " + indexdb + '.old'

def listRevokedCerts():
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

def listAllCerts():
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

if options.listall:
    listAllCerts()

if options.listrevoked:
    listRevokedCerts()

if options.serial:
    revokeCert(str(options.serial))

if options.showserial:
    print "Current SSL serial number (in hex): " + readSerial()

if options.printindex:
    print "Current index file (" + indexdb + "):"
    printIndexDB()

if options.printcert:
    print_cert ( options.printcert )

def send_mail(send_from, send_to, subject, text, attachment=[]):
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
    msg['CC'] = mail_cc
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    text = text.replace('EMAILRECIPIENT', options.cname)
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
    print 'Sending e-mail with attachment(s) to %s' % options.emailaddress
    smtp = smtplib.SMTP(mail_server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()

if options.emailaddress:
    mail_attachment = []
    mail_to = options.emailaddress
    # First check if we've generated a ZIP file (include just one attachment) or not (include all generated files)
    if options.zip:
        mail_attachment.append(working + '/' + options.fprefix + options.fname + '.zip')
        send_mail(mail_from, mail_to, 'StoneVPN: generated files for ' + str(options.cname), mail_msg, mail_attachment)
    else:
        # Generate a list of filenames to include as attachments
        import glob
        for name in glob.glob(working + "/" + options.fprefix + options.fname + ".*"):
            mail_attachment.append(name)
        # Also include the CA certificate
        mail_attachment.append(cacertfile)
        send_mail(mail_from, mail_to, 'StoneVPN: generated files for ' + str(options.cname), mail_msg, mail_attachment)

if options.route:
    from IPy import IP
    ip=IP(options.route).strNormal(2)
    route = str(ip).split('/')
    nospaces_cname =  options.cname.replace(' ', '_')
    # check if ccd dir exists:
    if not os.path.exists(ccddir):
        print "Client configuration directory didn't exist, making ..."
        os.mkdir(ccddir)
    f=open(ccddir + '/' + nospaces_cname, 'w')
    f.write("push route \"" + route[0] + " " + route[1] + "\"\n")
    f.close()
    print "Wrote extra route(s) to " + ccddir + "/" + nospaces_cname
