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
unprivilegedrequest = '0101'
unprivilegedanswer = '0102'
privilegedrequest = '0103'
privilegedanswer = '0104'

switchattributes = { 'switch-type' : ('0001','string'), 
                    'switch-name' : ('0003','string'), 'switch-mac' : ('0004','mac'), 
                    'switch-ip' : ('0006','ip'), 
                    'switch-netmask' : ('0007','ip'), 'switch-gateway' : ('0008','ip'), 
                    'switch-password' : ('000a', 'string'),
                    'switch-port-statuses' : ('0c00', 'port-status'),
                    'switch-firmware' : ('000d','string'),
                    'switch-port-count' : ('6000','raw')}


# initialize a socket
# SOCK_DGRAM specifies that this is UDP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# set socket options (allows us to send broadcasts)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# set socket timeout
s.settimeout(0.2)

# bind to SRCPORT
s.bind(('',SRCPORT))

def send_data(senddata): # {{{
    """Send the data out via SOCKET"""
    # send the data
    s.sendto(senddata,(DESTIP, DESTPORT))
    try:
        result = s.recv(1024)
        return result
    except socket.timeout:
        print 'SOCKET TIMED OUT'
# }}}

def senddata(reqtype,datalist): # {{{
    """This function builds the data to send them out via send_data"""
    increase_sequence()
    nsdpnoerror = '000000000000'
    nsdpseperator = '00000000'
    enddata = 'ffff0000'
    nsdpheader = 'NSDP'.encode('hex')
    data = reqtype 
    data += nsdpnoerror + mymac + destmac 
    data += sequence + nsdpheader + nsdpseperator 
    if isinstance(datalist[0], tuple):
        for datapair in datalist:
            if len(datapair[1]) < 2:
                length=0
            else:
                length=len(datapair[1])/2
            data += datapair[0] + hex(length)[2:].rjust(4,'0')
            data += datapair[1]
        data += enddata
        result = send_data(binascii.unhexlify(data))
    else:
        if len(datalist[1]) < 2:
            length=0
        else:
            length=len(datalist[1])/2
        data += datalist[0] + hex(length)[2:].rjust(4,'0')
        data += datalist[1]
        data += enddata
        result = send_data(binascii.unhexlify(data))
    return result
# }}}

def parsedata(hexvalue): # {{{
    """This function parses the hexdata we get back from the switch.
    hexvalue : hexvalue from the switch
    returns : a dictionary with the parse results
    """
    if hexvalue == None:
            dataresult = { 'ERROR' : 'NO RESULT' }
            return dataresult
    data = binascii.hexlify(hexvalue)
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
        dataresult.update({ 'ERROR' : data[7:10] })
    return dataresult
# }}}

def convert_hex(hexvalue, target): # {{{
    """This function converts hexdata to a target type
    hexvalue : the value we want to convert
    target : target type, any of 'ip', 'string', 'cipher', 'mac'
    """
    if target == 'ip':
        result = str(int('0x' + hexvalue[:2],0)) + '.' + str(int('0x' + hexvalue[2:4],0)) + '.' + str(int('0x' + hexvalue[4:6],0)) + '.' + str(int('0x' + hexvalue[6:8],0))
    elif target == 'string':
        result = binascii.unhexlify(hexvalue)
    elif target == 'cipher':
        result = int(hexvalue, 16)
    elif target == 'mac':
        result = ''
        while len(hexvalue) > 2:
            result += hexvalue[:2] + ':'
            hexvalue = hexvalue[2:]
        result += hexvalue
    elif target == 'port-status':
        result = []
        for port in hexvalue:
            if port[2:4] == '05':
                linkstat = '1000MBIT'
            elif port[2:4] == '04':
                linkstat = '100MBIT'
            elif port[2:4] == '03':
                linkstat = '10MBIT'
            elif port[2:4] == '00':
                linkstat = 'NO LINK'
            else:
                linkstat = 'UNKNOWN'
            result.append(( 'Port ' + str(port[:2]), linkstat))

    else:
        result = hexvalue

    return result
# }}}

def increase_sequence(): # {{{
    """This function does nothing than increase the sequence number we use"""
    global sequence
    sequence = hex(int(sequence) + 1)[2:].rjust(8,'0')
# }}}

def print_result(result): # {{{
    global destmac
    resultdict = parsedata(result)

    if 'ERROR' in resultdict:
        if resultdict['ERROR'] in switchattributes.key():
            print 'ERROR with ' + switchattributes[resultdict['ERROR']]
        print 'ERROR: ' + resultdict['ERROR']
    elif resultdict['packettype'] == privilegedanswer:
        print 'Successfull'
    else:
        for key in switchattributes.keys():
            if switchattributes[key][0] in resultdict:
                if key == 'switch-mac':
                   destmac = resultdict[switchattributes[key][0]]
                convertdata = convert_hex(resultdict[switchattributes[key][0]],switchattributes[key][1])
                if type(convertdata).__name__ == 'list':
                    print key + ': '
                    for element in convertdata:
                        print ' -> ' + element[0] + ': ' + element[1]
                else:
                    print key + ': ' + convertdata
# }}}

def do_discovery(): # {{{
    """This function discovers the available switches"""
    # Discovery needs two different requests...i have no idea why..
    discoveryresult = senddata(unprivilegedrequest,(('0001',''),('0002',''),('0003',''),('0004',''),('0005',''),('0006',''),('0007',''),('0008',''),('000b',''),('000c',''),('000d',''),('000e',''),('000f',''),('7400','')))

    discoveryresult = senddata(unprivilegedrequest,(('0001',''),('0002',''),('0003',''),('0004',''),('0005',''),('0006',''),('0007',''),('0008',''),('000b',''),('000c',''),('000d',''),('000e',''),('000f','')))
    # 
    print_result(discoveryresult)
# }}}

def do_authenticate(password): # {{{
    """This function tries to authenticate to the switch
    password : the password to try
    """
    print 'Authenticating...'
    authenticationresult = senddata(privilegedrequest,(switchattributes['switch-password'][0],password.encode('hex')))
    print_result(authenticationresult)
# }}}

def do_getPortCount(): # {{{
    """This function returns the numbers of ports available"""

    result = senddata(unprivilegedrequest,((switchattributes['switch-port-count'][0],''),))
    print_result(result)
# }}}

def do_getLinkStatus(): # {{{
    """This function returns the actual link statuses of all ports"""
    linkstatus = '0c00'
    result = senddata(unprivilegedrequest,((linkstatus,''),))

    print_result(result)
# }}}

def do_getPortCounter():
    testresult = senddata(unprivilegedrequest,('1000',''))
    print str(binascii.hexlify(testresult))
    resultdict = parsedata(testresult)

    for key in resultdict.keys():
        print key + ' ' + str(resultdict[key])

# MAIN
do_discovery()
print '#########'
do_authenticate('password')
print '#########'
do_getPortCount()
print '#########'
do_getLinkStatus()
print '#########'
do_getPortCounter()

s.close()
