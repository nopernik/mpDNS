#!/usr/bin/env python

# mpDNS aka Multipurpose DNS
#
# Simple, configurable "clone & run" DNS Server with multiple useful features
# - names.db -> holds all custom records (see for examples)
# - Simple wildcards like *.example.com
# - Support for unicode dns requests
# - Custom actions aka macro:
#   - {{shellexec::dig google.com +short}}		 # Execute shell command and respond with result
#   - {{eval::res = '1.1.1.%d' % random.randint(0,256)}} # Evaluate your python code
#   - {{file::/etc/passwd}}				 # Respond with localfile contents
#   - {{resolve}}					 # Forward DNS request to local DNS
#   - {{resolve::example.com}}				 # Resolve example.com instead of original record
#   - {{echo}}						 # Response back with peer address
#   - {{shellexec::echo %PEER% %QUERY%}}		 # Use of variables
# - Supported query types: A, CNAME, TXT
# - Update names.db records without restart/reload with 'nodns.py -e'
#
# Heavily based on https://github.com/circuits/circuits/blob/master/examples/dnsserver.py
#
# Usage: mpdns.py
#  - Edit names.db with 'mpdns.py -e' no restart required
#
# Twitter: @nopernik
# Blog: https://korznikov.com
#

from __future__ import print_function

import sys, os
from socket import gethostbyname_ex
import random
from dnslib import QTYPE, RR, A, TXT, DNSHeader, DNSRecord, DNSQuestion, CNAME

from circuits import Component, Debugger, Event
from circuits.net.events import write
from circuits.net.sockets import UDPServer

import re

from pprint import pprint

__author__ = "@nopernik"
__license__ = "GPL"
__version__ = "1.0"

rootPath = os.path.dirname(os.path.realpath(__file__))
hostFile = rootPath + '/names.db'
serverIP = '0.0.0.0'
logFile = '/tmp/dns-server.log'
PORT = 53

if '-e' in sys.argv[1:]:
   print('names.db location: %s' % hostFile)
   os.system('nano %s' % hostFile)
   exit()

try:
   open(logFile,'w').close()
except:
   pass

db = {}
qTypeDict = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',
                 16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY', 28:'AAAA',
                 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX', 37:'CERT', 38:'A6',
                 39:'DNAME', 41:'OPT', 42:'APL', 43:'DS', 44:'SSHFP',
                 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC', 48:'DNSKEY', 49:'DHCID',
                 50:'NSEC3', 51:'NSEC3PARAM', 52:'TLSA', 55:'HIP', 99:'SPF',
                 249:'TKEY', 250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY',
                 257:'CAA', 32768:'TA', 32769:'DLV'}
                
                

def parseDBFile():
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

def checkMacro(q,query,peer):
   query = str(query)
   if query[-1] == '.': query = query[:-1]
   
   # check if we should do with {{data}}
   macro = re.match('{{([^#]*)}}.*$',q)
   if not macro:
      return q
   argList = macro.group(1).split('::')
   macroType = argList[0]

   payload = ''
   if len(argList) > 1:
      payload = argList[1]
   
   variables = {'%PEER%':peer[0],'%QUERY%':query}
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
   elif macroType == 'file' and payload:
      if os.path.isfile(payload):
         with open(payload,'rb') as f:
            res = f.read()
      else:
         res = '127.0.0.1'
         print('File %r not found' % payload)
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
   return str(res)

def dbTest(q):
   global db
   db = {}

   parseDBFile()
   
   query = str(q)
   query = query[:-1] if query[-1] == '.' else query
   res = []


   if not query in db:
   #if not db.has_key(query):
      for qHost in db.keys():
         if qHost.startswith('*.') and query.endswith(qHost[2:]):
            res = [i for i in db[qHost]]
   else:
      res = [i for i in db[query]]
   return res

def customParse(q):
   id = int(q[:2].encode('hex'),16)
   q = bytearray(q[12:])
   l = len(q)
   qType = 0
   res = ''
   while 1:
      i = q[0]
      if not i:
         break
      q = q[1:]
      res += q[:i] + '.'
      q = q[i:]
   qType = ( q[1] << 8 ) + q[2]
   return {'id':id,'q':str(res),'qtype':qType}
   
def printOut(peer,qType,query,response):
    peerLen = len("%s:%d"%(peer[0],peer[1]))
    host = '%s:%d' % (peer[0],peer[1])
    printData = "- Request from %s -> %s\t-> %s (%s)" % (host.ljust(20), str(query), response , qTypeDict[qType])
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
           # Handle non latin characters, and respond with SERVFAIL
           data = customParse(data)
           printOut(peer,data['qtype'],data['q'],'SERVFAIL')
           reply = DNSRecord(DNSHeader(id=data['id'],qr=1,aa=1,ra=1,rcode=2,qtype=data['qtype']),q=DNSQuestion(data['q']))
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
              newAddr = checkMacro(cnameAddress[0],dHost,peer)
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
              record = checkMacro(tmprecord,qname,peer)
              n = 255
              if len(record) > 20: 
                 printData += [ record[:15]+'...(%d)' % len(record) ]
              else:
                 printData = [record]
              if len(record) > n:
                 record = [record[i:i+n] for i in range(0, len(record), n)]
              reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(record if isinstance(record,list) else [record,])))
              
           printOut(peer,queryType,str(qname),printData)

        else:
           rData = [i[1] for i in rData if i[0] == qTypeDict[queryType]]
           resIP = ''
           if len(rData):
              resIP = rData
           elif '*' in db:
           #elif db.has_key('*'): #python2 only
              resIP = [i[1] for i in dbTest('*') if i[0] == 'A']
           for tmpip in resIP:
              ip = checkMacro(tmpip,qname,peer)
              # Add A Record
              reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip)))
           if resIP: 
              printOut(peer,queryType,str(qname),', '.join(resIP))
           else:
              printOut(peer,queryType,str(qname),'NONE')

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
#for key,val in db.iteritems(): #python2 only
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

DNSServer((serverIP, PORT), verbose=True).run()
