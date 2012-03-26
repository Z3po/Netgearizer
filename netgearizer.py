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
sequence = '00000000'
mymac = get_mac()
destmac = '000000000000'
unprivilegedreq = '0101'
unprivilegedans = '0102'
privilegedreq = '0103'
privilegedans = '0104'

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

def senddata(reqtype,mymac,datalist):
    increase_sequence()
    nsdpnoerror = '000000000000'
    nsdpseperator = '00000000'
    enddata = 'ffff0000'
    nsdpheader = 'NSDP'.encode('hex')
    data = reqtype 
    data += nsdpnoerror + mymac + destmac 
    data += sequence + nsdpheader + nsdpseperator 
    for datapair in datalist:
        if len(datapair[1]) < 2:
            length=0
        else:
            length=len(datapair[1])/2
        data += datapair[0] + hex(length)[2:].rjust(4,'0')
        data += datapair[1]
    data += enddata
    result = send_data(binascii.unhexlify(data))
    return result

def parsedata(hexdata):
    if hexdata == None:
            dataresult = { 'ERROR' : 'NO RESULT' }
            return dataresult
    data = binascii.hexlify(hexdata)
    nsdpnoerror = '000000000000'
    dataresult = { 'packettype' : data[:4] }
    data = data[4:]
    if data[:12] == nsdpnoerror:
        data = data[36:]
        if data[:8] == sequence:
            data = data[24:]
            while data[:8] != 'ffff0000':
                length = 2*int('0x'+data[4:8],0)
                if data[:4] in dataresult:
                    if isinstance(dataresult[data[:4]],list):
                        dataresult[data[:4]].append(data[8:(8+length)])
                    else:
                        temp = dataresult[data[:4]]
                        dataresult.update({ data[:4] : [temp,data[8:(8+length)]] })
                else:
                    dataresult.update({ data[:4] : data[8:(8+length)] })
                data = data[(8+length):]
        else:
            print 'Not a result to my sequence!'
    else:
        dataresult.update({ 'ERROR' : data[:12] })
    return dataresult

def hex_to_ip(hexvalue):
    ip = str(int('0x' + hexvalue[:2],0)) + '.' + str(int('0x' + hexvalue[2:4],0)) + '.' + str(int('0x' + hexvalue[4:6],0)) + '.' + str(int('0x' + hexvalue[6:8],0))
    return ip

def hex_to_text(hexvalue):
    text = binascii.unhexlify(hexvalue)
    return text

def increase_sequence():
    global sequence
    sequence = hex(int(sequence) + 1)[2:].rjust(8,'0')


def do_discovery():
    global destmac
    switchtype = '0001'
    switchname = '0003'
    switchmac = '0004'
    switchip = '0006'
    switchnetmask = '0007'
    switchgateway = '0008'
    switchfirmver = '000d'
    
    startdiscoveryresult = senddata(unprivilegedreq,mymac,(('0001',''),('0002',''),('0003',''),('0004',''),('0005',''),('0006',''),('0007',''),('0008',''),('000b',''),('000c',''),('000d',''),('000e',''),('000f',''),('7400','')))
    resultdict = parsedata(startdiscoveryresult)

    enddiscoveryresult = senddata(unprivilegedreq,mymac,(('0001',''),('0002',''),('0003',''),('0004',''),('0005',''),('0006',''),('0007',''),('0008',''),('000b',''),('000c',''),('000d',''),('000e',''),('000f','')))
    resultdict = parsedata(enddiscoveryresult)


    if 'ERROR' in resultdict:
        print 'ERROR: ' + resultdict['ERROR']
    else:
        if resultdict['packettype'] == unprivilegedans:
            if switchtype in resultdict:
                print 'switch type: ' + hex_to_text(resultdict[switchtype])
            if switchname in resultdict:
                print 'switch name: ' + hex_to_text(resultdict[switchname])
            if switchmac in resultdict:
                print 'switch mac: ' + resultdict[switchmac]
                destmac = resultdict[switchmac]
            if switchip in resultdict:
                print 'switch ip: ' + hex_to_ip(resultdict[switchip])
            if switchnetmask in resultdict:
                print 'switch netmask: ' + hex_to_ip(resultdict[switchnetmask])
            if switchgateway in resultdict:
                print 'switch gateway: ' + hex_to_ip(resultdict[switchgateway])
            if switchfirmver in resultdict:
                print 'switch firmware version: ' + hex_to_text(resultdict[switchfirmver])
        else:
            print 'not our reply!'

def do_authenticate(password):
    authenticationresult = senddata(privilegedreq,mymac,(('000a',password.encode('hex')),))
    resultdict = parsedata(authenticationresult)

    if 'ERROR' in resultdict:
        print 'ERROR: ' + resultdict['ERROR']
    else:
        if resultdict['packettype'] == privilegedans:
            print 'Successfully authenticated!'
        else:
            print 'not our reply!'

def do_getPortCount():
    portcount = '6000'

    portstatsresult = senddata(unprivilegedreq,mymac,((portcount,''),))
    resultdict = parsedata(portstatsresult)

    if 'ERROR' in resultdict:
        print 'ERROR: ' + resultdict['ERROR']
    else:
        if resultdict['packettype'] == unprivilegedans:
            if portcount in resultdict:
                print 'Number of Switch ports: ' + resultdict[portcount]
            else:
                print 'No valid number of switch ports found'
        else:
            print 'not our reply!'

def do_getLinkStatus():
    linkstatus = '0c00'
    portstatsresult = senddata(unprivilegedreq,mymac,((linkstatus,''),))
    resultdict = parsedata(portstatsresult)

    if 'ERROR' in resultdict:
        print 'ERROR: ' + resultdict['ERROR']
    else:
        if resultdict['packettype'] == unprivilegedans:
            if linkstatus in resultdict:
                for port in resultdict[linkstatus]:
                    if port[2:4] == '05':
                        linkstat = '1000MBIT'
                    elif port[2:4] == '04':
                        linkstat = '100MBIT'
                    elif port[2:4] == '03':
                        linkstat = '10MBIT'
                    elif port[2:4] == '00':
                        linkstat = 'NO LINK'
                    print port[:2] + ': ' + linkstat


# MAIN
do_discovery()
print '#########'
do_authenticate('password')
print '#########'
do_getLinkStatus()

s.close()
