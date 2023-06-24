#!/usr/bin/env python3

from __future__ import print_function

import sys, os
import socket
from socket import gethostbyname_ex
import random
from dnslib import QTYPE, RR, A, AAAA, NS, TXT, DNSHeader, DNSRecord, DNSQuestion, CNAME, MX, RRSIG
import base64
import zlib
import math
import shlex
from netaddr import IPAddress as IP
import traceback

from circuits import Component, Debugger, Event
from circuits.net.events import write
from circuits.net.sockets import UDPServer
import helpers.colors as colors
import re

from pprint import pprint

__author__ = "@nopernik"
__license__ = "GPL"
__version__ = "1.2.1"

rootPath = os.path.dirname(os.path.realpath(__file__))
hostFile = rootPath + '/names.db'

sys.stderr.write('[+] Multipurpose DNS by @nopernik\n\n')
sys.stderr.flush()

if not os.path.exists(hostFile):
    print("[-] names.db does not found.\nUse names.db.example as a template and copy it to 'names.db' file.")
    exit(1)

serverIP = ''

if '-h' in sys.argv[1:] or '--help' in sys.argv[1:]:
    print('Usage:\n ./{} [--host 1.2.3.4]'.format(os.path.basename(__file__)))
    exit(1)

if '--host' in sys.argv[1:]:
    serverIP = sys.argv[sys.argv.index('--host')+1]

logFile = '/tmp/dns-server.log'
PORT = 53

with open('/tmp/dns-server.pid','wb') as pidfile:
    pidfile.write(str(os.getpid()).encode())


if '-e' in sys.argv[1:]:
    print('names.db location: %s' % hostFile)
    os.system('nano %s' % hostFile)
    exit()

try:
    open(logFile,'w').close()
except:
    pass

db = {}

def qTypeDict(qtype):
    qlist = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',
            16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY', 28:'AAAA',
            29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX', 37:'CERT', 38:'A6',
            39:'DNAME', 41:'OPT', 42:'APL', 43:'DS', 44:'SSHFP',
            45:'IPSECKEY', 46:'RRSIG', 47:'NSEC', 48:'DNSKEY', 49:'DHCID',
            50:'NSEC3', 51:'NSEC3PARAM', 52:'TLSA', 55:'HIP', 99:'SPF',
            249:'TKEY', 250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY',
            257:'CAA', 32768:'TA', 32769:'DLV', 65:'HTTPS'}
    if qtype in qlist:
        return qlist[qtype]
    return 'TYPE{}'.format(qtype)


def parseDBFile(hostFile=hostFile):
    with open(hostFile,'r') as f:
        for line in f.read().split('\n'):
            if re.match('^\s*[#;]',line): continue
            match = re.match('^\s*([^\s]+)\s+([^\s]+)\s+([^#]+)',line)
            if match:
                mhost = match.group(1)
                mtype = match.group(2)
                mdata = match.group(3).strip()
                
                if not mhost in db:
                #if not db.has_key(mhost):
                    db.update( { mhost:[] })
                # ignore duplicates
                if not (mtype,mdata) in db[mhost]:
                    db[mhost] += [(mtype,mdata)]

def localDNSResolve(dhost):
    return random.choice(gethostbyname_ex(dhost)[-1])

def longToIP(ipLong):
    ipString = []
    for i in range(8):
        ipString += [('%04x'%(ipLong & 0xffff))]
        ipLong = ipLong >> 16
    return ':'.join(ipString[::-1])

def isValidIP(s):
    try:
        IP(s)
        return True
    except:
        return False

def checkMacro(queryType,q,query,peer):
    queryType = qTypeDict(queryType)
    query = str(query)
    if query[-1] == '.': query = query[:-1]
   
    # check if we should do something with {{data}}
    macro = re.match('{{([^#]*)}}.*$',q)
    if not macro:
        return q
    argList = macro.group(1).split('::')
    macroType = argList[0]
    # We've got macro %s" % macroType
    payload = ''
    if len(argList) > 1:
        payload = argList[1]
    variables = {'%PEER%':peer[0],'%QUERY%':shlex.quote(query), '%QUERYTYPE%': queryType}
    for var in variables.keys():
        if var in payload:
            payload = payload.replace(var,variables[var])
         
    if macroType == 'resolve':
        if not payload or payload == 'self':
            #resolve
            #resolve::self
            return localDNSResolve(query)
        else:
            #resolve::google.com
            return localDNSResolve(payload)
    elif macroType == 'echo':
        return peer[0]
    elif payload and macroType in ['gzip','file']:
        if os.path.isfile(payload):
            with open(payload,'rb') as f:
                if macroType == 'gzip':
                    gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
                    res = base64.b64encode(gzip_compress.compress(f.read()) + gzip_compress.flush())
                else:
                    res = base64.b64encode(f.read())
        else:
            res = '127.0.0.1'
            print('File %r not found' % payload)
    elif macroType == 'filelist' and payload:
        # return file content 
        # example:
        #  line1 other data
        #  line2 comment
        #  results in ['line1','line2']
        if os.path.isfile(payload):
            with open(payload,'rb') as f:
                res = [i.strip().split(b' ')[0].decode() for i in f.read().split(b'\n') if i and not i.strip().startswith(b'#')]
        else:
            res = '127.0.0.1'
            print('File %r does not exists' % payload)

    elif macroType == 'eval' and payload:
        res = '127.0.0.1' # in case someone forget 'res =' in payload
        _locals = locals()
        exec(payload,globals(),_locals)
        res = _locals["res"]
    elif macroType == 'shellexec' and payload:
        res = os.popen(payload).read().strip()
    else:
        print("Unhandled macroType, defaulting to 127.0.0.1")
        res = '127.0.0.1'
    if queryType == 'A' and isValidIP(res):
        return res
    elif queryType == 'TXT' and len(res) == 0:
        return ''
    return res

def dbTest(q):
    global db
    db = {}

    parseDBFile()
    query = str(q).lower()
    query = query[:-1] if query[-1] == '.' else query
    res = []
    if not query in db:
    #if not db.has_key(query):
        for qHost in db.keys():
            if qHost.startswith('*.') and query.endswith(qHost[2:]):
                res += [i for i in db[qHost]]
    else:
        res = [i for i in db[query]]
    return res

def customParse(q):
    qid = int(q[:2].hex(),16)
    print(qid)
    q = q[12:]
    l = len(q)
    qType = 0
    res = b''
    while 1:
        i = q[0]
        if not i:
            break
        q = q[1:]
        res += q[:i] + b'.'
        q = q[i:]
    qType = ( q[1] << 8 ) + q[2]
    return {'id':qid,'q':res,'qtype':qType}
   
def printOut(peer,qType,query,response = None):
    peerLen = len("%s:%d"%(peer[0],peer[1]))
    host = '%s:%d' % (peer[0],peer[1])
    if response is None:
        printData = ("{host: <30} {qtype: <6} {query}\t{response}".format(host=colors.gray(host), query = colors.darkorange(str(query)), qtype = colors.orangebold(qTypeDict(qType).ljust(6)), response = colors.darkgray(response)))
    else:
        printData = "{host: <30} {qtype: <6} {query}\t{response}".format(host=colors.gray(host), query = colors.green(str(query)), qtype = colors.orangebold(qTypeDict(qType).ljust(6)), response = colors.cyan(response))
    print(printData, file=sys.stdout )
    p = open(logFile,'a')
    p.write(printData+'\n')
    p.close()

class query(Event):

    """query Event"""

class DNS(Component):

    """DNS Protocol Handling"""

    def read(self, peer, data):
        try:
            self.fire(query(peer, DNSRecord.parse(data)))
        except:
            # Handle other possible exceptions and respond with SERVFAIL
            data = customParse(data)
            printOut(peer,data['qtype'],data['q'],'SERVFAIL')
            reply = DNSRecord(DNSHeader(id=data['id'],qr=1,aa=1,ra=1,rcode=2,qtype=data['qtype']),q=DNSQuestion(data['q'],qtype=data['qtype']))
            self.fire(write(peer, reply.pack()))

class Dummy(Component):

    def query(self, peer, request):
        id = request.header.id
        qname = request.q.qname
        queryType = request.q.qtype
        reply = DNSRecord( DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q )

        def cnameRecursion(dHost):
            global tmpRes # used for overwriting previous recursion value
            tmpData = dbTest(dHost)
            # First: get CNAME of desired host
            cnameAddress = [i[1] for i in tmpData if i[0] == 'CNAME']
            tmpRes = (dHost,tmpData)
            if cnameAddress:
                newAddr = checkMacro(queryType,cnameAddress[0],dHost,peer)
                reply.add_answer(RR(dHost, QTYPE.CNAME, rdata=CNAME(newAddr)))
                # Second: get desired QTYPE from desired host
                printOut(peer,QTYPE.CNAME,str(dHost),newAddr)
                cnameRecursion(newAddr)
            return tmpRes

        qname,rData = cnameRecursion(qname)

        if queryType == QTYPE.TXT: # TXT
            rData = [i[1] for i in rData if i[0] == 'TXT']
            # Add TXT Record
            printData = []
            for tmprecord in rData:
                record = checkMacro(queryType,tmprecord,qname,peer)
                n = 255
                if len(record) > 20: 
                    printData += [ str(record[:15]) + '...(%d)' % len(record) ]
                else:
                    printData = [record]
                if len(record) > n:
                    record = [record[i:i+n] for i in range(0, len(record), n)]
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(record if isinstance(record,list) else [record,])))
            printOut(peer,queryType,str(qname),printData)

        elif queryType == QTYPE.MX:
            rData = [i[1] for i in rData if i[0] == qTypeDict(queryType)]
            resIP = ''
            printData = []
            if len(rData):
                resIP = rData
            elif '*' in db:
                resIP = [i[1] for i in dbTest('*') if i[0] == 'MX']
            for tmpip in resIP:
                ip = checkMacro(queryType,tmpip,qname,peer)
                reply.add_answer(RR(qname, QTYPE.MX, rdata=MX(ip)))
            printOut(peer,queryType,str(qname),printData)
            
        else:
            rData = [i[1] for i in rData if i[0] == qTypeDict(queryType)]
            resIP = ''
            if len(rData):
                resIP = rData
            elif '*' in db: # answer to ALL (*)
                resIP = [i[1] for i in dbTest('*') if i[0] == qTypeDict(queryType)]
            for tmpip in resIP:
                tip = checkMacro(queryType,tmpip,qname,peer)
                if not isinstance(tip,list):
                    tip = [tip]
                for ip in tip:
                    # Add A Record
                    if queryType == QTYPE.NS:
                        reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(ip)))
                    elif queryType == QTYPE.AAAA:
                        if isValidIP(ip):
                            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(ip)))
                        else:
                            # Handle invalid IPv6, encode it in hex and send in form of IPv6
                            # Converting 'simpletext' -> ::7369:6d70:6c65:7465:7874
                            # To be used in 'file' macro
                            print("Invalid IPv6 provided: {!r}... Answering as HEX -> IPv6".format(ip[:20]))
                            n = 16
                            # if len(ip) > n:
                            if isinstance(ip,str):
                                ip = ip.encode()
                            record = [longToIP(int((ip[i:i+n]).hex(),16)) for i in range(0, len(ip), n)]
                            for i in record:
                                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(i)))
                    else:
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=30))
            if resIP: 
                printOut(peer,queryType,str(qname),response = ', '.join(resIP))
            else:
                printOut(peer,queryType,str(qname), response = None)

        # Send To Client
        self.fire(write(peer, reply.pack()))


class DNSServer(Component):

    def init(self, bind=None, verbose=False):
        self.bind = bind or (serverIP, PORT)
        self.transport = UDPServer(self.bind).register(self)
        self.protocol = DNS().register(self)
        self.dummy = Dummy().register(self)
    def started(self, manager):
        print("\nDNS Server Started!", file=sys.stdout)

    def ready(self, server, bind):
        print("Ready! Listening on {0:s}:{1:d}".format(*bind), file=sys.stdout)

print("Reading hosts from %r:\n" % hostFile)
parseDBFile()
print('Loaded:\n')
for key,val in db.items():
    for v in val:
        if len(v[1]) > 255:
            p = v[1][:10]+'...(%d) 255 bytes SPLIT!' % len(v[1])
        elif len(v) > 65217:
            p = v[1][:10]+'...(%d) MAX SIZE 65217 bytes' % len(v[1])
        elif len(v) > 50: 
            p = v[1][:10]+'...(%d)' % len(v[1])
        else:
            p = v[1]
        print('%s%s%r' % (key.ljust(25),v[0].ljust(8),p))
for k in db:
    print(colors.green('[+] {}:'.format(k)))
    for v in db[k]:
        print('{} -> {}'.format(v[0].rjust(8).ljust(8),v[1]))


try:
    DNSServer((serverIP, PORT), verbose=True).run()
except socket.error:
    print('[-] Unable to bind on serverIP\nTry overriding bind host with --host 1.2.3.4\n')
    print(traceback.format_exc())