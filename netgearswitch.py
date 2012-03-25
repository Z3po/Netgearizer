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
sequence = '00000001'
mymac = get_mac()
destmac = '000000000000'

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

def constructdata(sequence,adddata,reqtype='0101',mymac='0',destmac='0'):
    nsdpnoerror = '000000000000'
    nsdpseperator = '00000000'
    enddata = 'ffff0000'
    nsdpheader = 'NSDP'.encode('hex')
    data = reqtype 
    data += nsdpnoerror + mymac.rjust(12,'0') + destmac.rjust(12,'0') 
    data += sequence + nsdpheader + nsdpseperator 
    data += adddata
    data += enddata
    return data

def parsedata(sequence,data):
    nsdpnoerror = '000000000000'
    dataresult = {}
    dataresult.update({ 'packettype' : data[:4] })
    data = data[4:]
    if data[:12] == nsdpnoerror:
        data = data[36:]
        if data[:8] == sequence:
            data = data[24:]
            while data[:8] != 'ffff0000':
                length = 2*int('0x'+data[4:8],0)
                dataresult.update({ data[:4] : data[8:(8+length)] })
                data = data[(8+length):]
        else:
            print 'Not a result to my sequence!'
    else:
        print 'Error! ' + data[:12]
    return dataresult



def do_discovery():
    global sequence, destmac
    discoveryheader = '0101'
    discoveryansheader = '0102'
    switchtype = '0001'
    switchname = '0003'
    switchmac = '0004'
    switchip = '0006'
    switchnetmask = '0007'
    switchgateway = '0008'
    switchfirmver = '000d'
    
    discoverydata = constructdata(sequence,'0001000000020000000300000004000000050000000600000007000000080000000b0000000c0000000d0000000e0000000f000074000000',discoveryheader,mymac,destmac)
    discoveryresult = send_data(binascii.unhexlify(discoverydata))
    if discoveryresult != None:
        result = binascii.hexlify(discoveryresult)
        resultdict = parsedata(sequence,result)

    sequence = hex(int(sequence) + 1)[2:].rjust(8,'0')

    discoverydata = constructdata(sequence,'0001000000020000000300000004000000050000000600000007000000080000000b0000000c0000000d0000000e0000000f0000',discoveryheader,mymac)
    enddiscoveryresult = send_data(binascii.unhexlify(discoverydata))
    if enddiscoveryresult != None:
        result = binascii.hexlify(enddiscoveryresult)
        resultdict = parsedata(sequence,result)

    if resultdict['packettype'] == discoveryansheader:
        if switchtype in resultdict:
            print 'switch type: ' + binascii.unhexlify(resultdict[switchtype])
        if switchname in resultdict:
            print 'switch name: ' + binascii.unhexlify(resultdict[switchname])
        if switchmac in resultdict:
            print 'switch mac: ' + resultdict[switchmac]
            destmac = resultdict[switchmac]
        if switchip in resultdict:
            print 'switch ip: ' + str(int('0x' + resultdict[switchip][:2],0)) + '.' + str(int('0x' + resultdict[switchip][2:4],0)) + '.' + str(int('0x' + resultdict[switchip][4:6],0)) + '.' + str(int('0x' + resultdict[switchip][6:8],0))
        if switchnetmask in resultdict:
            print 'switch netmask: ' + str(int('0x' + resultdict[switchnetmask][:2],0)) + '.' + str(int('0x' + resultdict[switchnetmask][2:4],0)) + '.' + str(int('0x' + resultdict[switchnetmask][4:6],0)) + '.' + str(int('0x' + resultdict[switchnetmask][6:8],0))
        if switchgateway in resultdict:
            print 'switch gateway: ' + str(int('0x' + resultdict[switchgateway][:2],0)) + '.' + str(int('0x' + resultdict[switchgateway][2:4],0)) + '.' + str(int('0x' + resultdict[switchgateway][4:6],0)) + '.' + str(int('0x' + resultdict[switchgateway][6:8],0))
        if switchfirmver in resultdict:
            print 'switch firmware version: ' + binascii.unhexlify(resultdict[switchfirmver])
    else:
        print 'not our reply!'

def do_authentication():
    authenticateheader = '0103'
    successheader = '0104'



# MAIN
do_discovery()

s.close()
