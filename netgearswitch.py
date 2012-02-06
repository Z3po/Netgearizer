#!/usr/bin/python
# GPL
# https://github.com/Z3po/Netgearizer

import socket
import binascii
import commands
import re

# addressing information
DESTIP = '<broadcast>'
DESTPORT = 63322
SRCPORT = 63321

# initialize a socket
# SOCK_DGRAM specifies that this is UDP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# set socket options (allows us to send broadcasts)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# set socket timeout
s.settimeout(0.2)

# bind to SRCPORT
s.bind(('',SRCPORT))

def get_mac():
    routeresult = commands.getoutput('/sbin/route -n')
    for line in routeresult.split('\n'):
        if re.match('0\.0\.0\.0.*',line):
            defaultroute = line
    defaultiface = defaultroute.split()[-1]
    ifaceresult = commands.getoutput('/sbin/ifconfig ' + defaultiface)
    for line in ifaceresult.split('\n'):
        if re.search('HWaddr',line):
            MAC = re.sub(':','',line.split()[-1])
            break
    return MAC

def send_data(senddata):
    # send the data
    s.sendto(senddata,(DESTIP, DESTPORT))
    try:
        result = s.recv(1024)
        return result
    except socket.timeout:
        print 'SOCKET TIMED OUT'

# MAIN
macaddress = get_mac()
discoverydata = '0101'
emptymac = '000000000000'

# enter the data content of the UDP packet as hex
firstdiscover = binascii.unhexlify(discoverydata + emptymac + macaddress + emptymac + '00000001' + 'NSDP'.encode('hex') + '000000000001000000020000000300000004000000050000000600000007000000080000000b0000000c0000000d0000000e0000000f000074000000ffff0000')
seconddiscover = binascii.unhexlify(discoverydata + emptymac + macaddress + emptymac + '00000002' + 'NSDP'.encode('hex') + '000000000001000000020000000300000004000000050000000600000007000000080000000b0000000c0000000d0000000e0000000f0000ffff0000')

data = firstdiscover

result = send_data(data)
print result
