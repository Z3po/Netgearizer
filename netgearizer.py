#!/usr/bin/python
# GPL
# https://github.com/Z3po/Netgearizer

import socket
import binascii
import commands
import re
import cmd
from sys import exit

class SwitchConfig(cmd.Cmd):
    
    # addressing information
    DESTIP = '<broadcast>'
    DESTPORT = 63322
    SRCPORT = 63321
    
    # global hex data
    sequence = '00000000'
    mymac = ''
    destmac = '000000000000'
    privilegedanswer = '0104'
    password = None
    portmirrorvalues = ('80','40','20','10','08','04','02','01')

    
    switchattributes = { 'switch-type' : ('0001','string'),
                        'switch-name' : ('0003','string'), 'switch-mac' : ('0004','mac'),
                        'switch-ip' : ('0006','ip'),
                        'switch-netmask' : ('0007','ip'), 'switch-gateway' : ('0008','ip'),
                        'new-switch-password' : ('0009', 'string'),
                        'switch-password' : ('000a', 'string'), 'switch-dhcp' : ('000b', 'dhcpoption'),
                        'switch-port-statuses' : ('0c00', 'port-status'),
                        'switch-firmware' : ('000d','string'),
                        'switch-restart' : ('0013','raw'), 'switch-factory-reset' : ('0400','raw'),
                        'switch-port-counter' : ('1000','port-counter'), 'switch-port-counter-reset' : ('1400','raw'),
                        'switch-port-mirror' : ('5c00', 'port-mirror'), 'switch-port-count' : ('6000','cipher')}
    
    
    def __init__(self):
        cmd.Cmd.__init__(self)
        # get own mac address
        self.mymac = self.__getMac()
        # initialize a socket
        # SOCK_DGRAM specifies that this is UDP
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # set socket options (allows us to send broadcasts)
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # set socket timeout
        self.connection.settimeout(1)
        # bind to SRCPORT
        self.connection.bind(('',self.SRCPORT))
        # do discovery
        self.__switchDiscovery()

    def __del__(self): # {{{
        """Destructor"""
        self.connection.close()
    # }}}
 
    def __getMac(self): # {{{
        """This function is needed to get the local mac address"""
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
    # }}}

    def __socketSend(self, __sendData): # {{{
        """Send the data out via SOCKET"""
        # send the data
        self.connection.sendto(__sendData,(self.DESTIP, self.DESTPORT))
        try:
            result = self.connection.recv(4096)
            return result
        except socket.timeout:
            print 'SOCKET TIMED OUT'
            print 'Are you connected to the switch?'
            exit(2)
    # }}}
 
    def __sendData(self, reqtype,datalist): # {{{
        """This function builds the data to send them out via __socketSend"""
        self.__increaseSequence()
        nsdpnoerror = '000000000000'
        nsdpseperator = '00000000'
        enddata = 'ffff0000'
        nsdpheader = 'NSDP'.encode('hex')
        if reqtype == 'set':
            data = '0103'
        elif reqtype == 'get':
            data = '0101'
    
        data += nsdpnoerror + self.mymac + self.destmac 
        data += self.sequence + nsdpheader + nsdpseperator 
        if reqtype == 'set':
            if self.password == None:
                print 'Please authenticate first'
                return None
            else:
                data += self.switchattributes['switch-password'][0] + hex(len(self.password)/2)[2:].rjust(4,'0')
                data += self.password
        if isinstance(datalist[0], tuple):
            for datapair in datalist:
                if len(datapair[1]) < 2:
                    length=0
                else:
                    length=len(datapair[1])/2
                data += datapair[0] + hex(length)[2:].rjust(4,'0')
                data += datapair[1]
            data += enddata
            result = self.__socketSend(binascii.unhexlify(data))
        else:
            if len(datalist[1]) < 2:
                length=0
            else:
                length=len(datalist[1])/2
            data += datalist[0] + hex(length)[2:].rjust(4,'0')
            data += datalist[1]
            data += enddata
            result = self.__socketSend(binascii.unhexlify(data))
        return result
    # }}}

    def __switchDiscovery(self): # {{{
        """This function discovers the available switches"""
        # Discovery needs two different requests...i have no idea why..
        discoveryresult = self.__sendData('get',(('0001',''),('0002',''),('0003',''),('0004',''),('0005',''),('0006',''),('0007',''),('0008',''),('000b',''),('000c',''),('000d',''),('000e',''),('000f',''),('7400','')))
    
        discoveryresult = self.__sendData('get',(('0001',''),('0002',''),('0003',''),('0004',''),('0005',''),('0006',''),('0007',''),('0008',''),('000b',''),('000c',''),('000d',''),('000e',''),('000f','')))
    
        self.__printResult(discoveryresult)
    # }}}

    def __parseData(self,hexvalue): # {{{
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
            if data[:8] == self.sequence:
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
            dataresult.update({ 'ERROR' : data[4:8] })
        return dataresult
    # }}}
    
    def __convertHex(self, hexvalue, target): # {{{
        """This function converts hexdata to a target type
hexvalue : the value we want to convert
target : target type, any of 'ip', 'string', 'cipher', 'mac'
"""
        if target == 'ip':
            result = str(int('0x' + hexvalue[:2],0)) + '.' + str(int('0x' + hexvalue[2:4],0)) + '.' \
            + str(int('0x' + hexvalue[4:6],0)) + '.' + str(int('0x' + hexvalue[6:8],0))
        elif target == 'string':
            result = binascii.unhexlify(hexvalue)
        elif target == 'cipher':
            result = str(int(hexvalue, 16))
        elif target == 'mac':
            result = ''
            while len(hexvalue) > 2:
                result += hexvalue[:2] + ':'
                hexvalue = hexvalue[2:]
            result += hexvalue
        elif target == 'dhcpoption':
            if hexvalue == '01':
                result = 'enabled'
            else:
                result = 'disabled'
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
        elif target == 'port-mirror':
            toPort = hexvalue[0:2]
            if toPort == '00':
                result = 'disabled'
            else:
                fromPort = str(self.portmirrorvalues.index(hexvalue[4:8]) + 1).rjust(2,'0')
                result = [ ( 'from Port', fromPort ),
                           ( 'toPort', toPort )]
        elif target == 'port-counter':
            result = []
            for port in hexvalue:
                sendstats = self.__convertHex(port[2:18],'cipher')
                receivestats = self.__convertHex(port[19:35],'cipher')
                crcerrors = self.__convertHex(port[36:53],'cipher')
                result.append(( 'Port ' + str(port[:2]), (('send', sendstats), ('receive', receivestats), ('crcerrors', crcerrors))))
        else:
            result = hexvalue
    
        return result
    # }}}
    
    def __increaseSequence(self): # {{{
        """This function does nothing than increase the sequence number we use"""
        self.sequence = hex(int(self.sequence, 16) + 1)[2:].rjust(8,'0')
    # }}}
    
    def __printResult(self, result): # {{{
        """This function prints the results
result: hexvalue we get from the switch
        """
        resultdict = self.__parseData(result)
    
        if 'ERROR' in resultdict:
            found = None
            for key in  self.switchattributes.keys():
                if resultdict['ERROR'] == self.switchattributes[key][0]:
                    found = key
            if found != None:
                print 'ERROR with ' + found
            else:
                print 'ERROR: ' + resultdict['ERROR']
        elif resultdict['packettype'] == self.privilegedanswer:
            print 'Successful'
        else:
            for key in self.switchattributes.keys():
                if self.switchattributes[key][0] in resultdict and len(resultdict[self.switchattributes[key][0]]) > 0:
                    if key == 'switch-mac':
                       self.destmac = resultdict[self.switchattributes[key][0]]
                    convertdata = self.__convertHex(resultdict[self.switchattributes[key][0]],self.switchattributes[key][1])
                    if type(convertdata).__name__ == 'list':
                        print key + ': '
                        for element in convertdata:
                            if type(element[1]).__name__ == 'tuple':
                                print ' -> ' + element[0] + ': '
                                for data in element[1]:
                                    print '   >> ' + data[0] + ': ' + data[1]
                            else:
                                print ' -> ' + element[0] + ': ' + element[1]
                    else:
                        print key + ': ' + convertdata
    # }}}

    def __splitLine(self,argumentcount,line): # {{{
        splitline = line.split()
        if len(splitline) > argumentcount:
            print 'Too many arguments!'
            return False
        else:
            if len(splitline) < argumentcount:
                count=len(splitline)
                while count < argumentcount:
                    splitline.append(None)
                    count += 1
            return splitline
    # }}}

    def do_quit(self, line): # {{{
        """Quit the application"""
        return True
    # }}}

    def do_EOF(self, line): # {{{
        return True
    # }}}

    def help_help(line): # {{{
        print 'well...are you kidding me?'
    # }}}

    def do_authenticate(self, line): # {{{
        """try to authenticate to the switch.
Syntax: authenticate $password
$password : the password to try"""
        self.password = line.encode('hex')
        print 'Authenticating...'
        result = self.__sendData('set',(self.switchattributes['switch-password'][0],self.password.encode('hex')))
        self.__printResult(result)
    # }}}
    
    def do_getSwitches(self, line): # {{{
        """Discover all available switches again.
Syntax: discovery"""
        self.__switchDiscovery()
    # }}}

    def do_getPortCount(self, line): # {{{
        """return the numbers of ports available.
Syntax: getPortCount"""
        result = self.__sendData('get',((self.switchattributes['switch-port-count'][0],''),))
        self.__printResult(result)
    # }}}
    
    def do_getLinkStatus(self, line): # {{{
        """return link statuses of all ports.
Syntax: getLinkStatus"""
        linkstatus = '0c00'
        result = self.__sendData('get',((linkstatus,''),))
    
        self.__printResult(result)
    # }}}
    
    def do_getPortStatistics(self, line): # {{{
        """show port statistics.
Syntax: getPortStatistics"""
        result = self.__sendData('get',('1000',''))
        self.__printResult(result)
    # }}}
 
    def do_getPortMirror(self, line): # {{{
        """show port mirror setup.
Syntax: getPortMirror"""
        result = self.__sendData('get',(self.switchattributes['switch-port-mirror'][0],''))
        self.__printResult(result)
    # }}}

    def do_setSwitchName(self, line): # {{{
        """set the switch name.
Syntax: setSwitchName $name
->$name : the name to set"""
        name = self.__splitLine(1,line)
        if not name:
            return False
        print 'Setting Switch Name...'
        result = self.__sendData('set',(self.switchattributes['switch-name'][0],name.encode('hex')))
        self.__printResult(result)
    # }}}
    
    def do_setPassword(self, line): # {{{
        """change the switch password.
Syntax: setPassword $password
->$password : the password to set"""
        password = self.__splitLine(1,line)
        print 'Setting Password...'
        result = self.__sendData('set',(self.switchattributes['new-switch-password'][0],password.encode('hex')))
        self.__printResult(result)
    # }}}

    def do_setDHCP(self, line): # {{{
        """change the DHCP settings.
Syntax: setDHCP $option
->$option : any of - disable, enable, renew"""
        option, ip, gateway, netmask = self.__splitLine(4,line)
        print 'Setting DHCP option...'
        if option == 'renew':
            setvalue='02'
        elif option == 'enable':
            setvalue='01'
        elif option == 'disable':
            if ip is not None and gateway is not None and netmask is not None:
#                result = self.__sendData(self.privilegedrequest,((self.switchattributes['switch-ip'][0],ip.encode('hex')),
#                (self.switchattributes['switch-netmask'][0],netmask.encode('hex')),(self.switchattributes['switch-gateway'][0],gateway.encode('hex')),
#                (self.switchattributes['switch-dhcp'][0],'00')))
                pass
            else:
                setvalue='00'
        else:
            print 'please use any of: renew, enable, disable'
            return False
        result = self.__sendData('set',(self.switchattributes['switch-dhcp'][0],setvalue))
        self.__printResult(result)
     # }}}

    def do_setRestart(self, line): # {{{
        """"restart the switch (or not).
Syntax: setRestart"""
        print 'Restarting switch...'
        result = self.__sendData('set',(self.switchattributes['switch-restart'][0],'01'))
        self.__printResult(result)
    # }}}

    def do_setFactoryDefaults(self, line): # {{{
        """reset to factory defaults.
Syntax: setFactoryDefaults"""
        result = self.__sendData('set',(self.switchattributes['switch-factory-reset'][0], '01'))
        self.__printResult(result)
    # }}}

    def do_setResetPortStatistic(self, line): # {{{
        """reset port counters.
Syntax: setPortCounterReset"""
        result = self.__sendData('set',(self.switchattributes['switch-port-counter-reset'][0], '01'))
        self.__printResult(result)
    # }}}

    def do_setPortMirror(self, line): # {{{
        """set port mirror.
Syntax: setPortMirror $option $fromPort $toPort
->$option : enable/disable
->$fromPort : the port you want to mirror
->$toPort : the port you want to mirror to"""
        option, fromPort, toPort = self.__splitLine(3,line)
        if option == 'enable':
            if fromPort == None or toPort == None:
                print 'please set fromPort and toPort'
                return False
            result = self.__sendData('set',(self.switchattributes['switch-port-mirror'][0], toPort.rjust(2,'0') + '00' + self.portmirrorvalues[int(fromPort)-1]))
            self.__printResult(result)
        elif option == 'disable':
            result = self.__sendData('set',(self.switchattributes['switch-port-mirror'][0], '000000'))
            self.__printResult(result)
        else:
            print 'please use enable or disable as option'
    # }}}

if __name__ == '__main__':
    SwitchConfig().cmdloop()
