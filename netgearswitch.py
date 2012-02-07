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

# global hex data
transactioncounter = '00000001'
macaddress = get_mac()
nsdpheader = 'NSDP'.encode('hex')
nsdpseperator = '00000000'

# initialize a socket
# SOCK_DGRAM specifies that this is UDP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# set socket options (allows us to send broadcasts)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# set socket timeout
s.settimeout(0.2)

# bind to SRCPORT
s.bind(('',SRCPORT))


def send_data(senddata):
    # send the data
    s.sendto(senddata,(DESTIP, DESTPORT))
    try:
        result = s.recv(1024)
        return result
    except socket.timeout:
        print 'SOCKET TIMED OUT'

def do_discovery():
    global transactioncounter
    discoveryheader = '0101'
    discoveryansheader = '0102'
    emptymac = '000000000000'
    switchtypestart = '00010008'
    switchtypeend = '0002'
    switchfirmverstart = '000d0007'
    switchfirmverend = '000e0000'
    
    startdiscoveryresult = send_data(binascii.unhexlify(discoveryheader + emptymac + macaddress + emptymac + transactioncounter + nsdpheader + nsdpseperator + '0001000000020000000300000004000000050000000600000007000000080000000b0000000c0000000d0000000e0000000f000074000000ffff0000'))
    if startdiscoveryresult != None:
        result = binascii.hexlify(startdiscoveryresult)
        if result[:4] == discoveryansheader:
            print 'got a successfull discovery'
            result = result[4:]
            if result[:12] == emptymac:
                result = result[12:]
                print 'My Mac is: ' + result[:12]
                result = result[12:]
                print 'The Switches MAC is: ' + result[:12]
                result = result[12:]
                if result[:8] == transactioncounter:
                    print 'Is a Reply to my own transaction!'
                    result = result[8:]
                    if result[:8] == nsdpheader:
                        print 'Is a NSDP reply!'
                        result = result[16:]
                        if result[:8] == switchtypestart:
                            result = result[8:]
                            length = result.find(switchtypeend)
                            print 'Switchtype: ' + binascii.unhexlify(result[:length])
                            result = result[length:]
        else:
            print 'got a strange reply: ' + result

    
    transactioncounter = str(int(transactioncounter) + 1).rjust(8,'0')
    print transactioncounter
    

    enddiscoveryresult = send_data(binascii.unhexlify(discoveryheader + emptymac + macaddress + emptymac + transactioncounter + nsdpheader + nsdpseperator + '0001000000020000000300000004000000050000000600000007000000080000000b0000000c0000000d0000000e0000000f0000ffff0000'))
    result = binascii.hexlify(enddiscoveryresult)
    if result[:4] == discoveryansheader:
        print 'got a successfull discovery'
        result = result[4:]
        if result[:12] == emptymac:
            result = result[12:]
            print 'My Mac should be: ' + result[:12]
            result = result[12:]
            print 'The Switches MAC is: ' + result[:12]
            result = result[12:]
            if result[:8] == transactioncounter:
                print 'Is a Reply to my own transaction!'
                result = result[8:]
                if result[:8] == nsdpheader:
                    print 'IS a NSDP reply!'
                    result = result[16:]
                    if result[:8] == switchtypestart:
                        result = result[8:]
                        length = result.find(switchtypeend)
                        print 'Switchtype: ' + binascii.unhexlify(result[:length])
                        result = result[length:]

    else:
        print 'got a strange reply: ' + result




def do_authentication():
    authenticateheader = '0103'
    successheader = '0104'



# MAIN
print do_discovery()
