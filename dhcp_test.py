#!/usr/bin/env python3
# Foundations of Python Network Programming, Third Edition
# https://github.com/brandon-rhodes/fopnp/blob/m/py3/chapter02/udp_local.py
# UDP client and server on localhost

import argparse, socket, binascii, sys
from struct import *
from random import randint
from uuid import getnode as get_mac
from datetime import datetime

MAX_BYTES = 65535
NOT_DHCP = -1
IS_DISCOVER = 1
IS_OFFER = 2
IS_REQUEST = 3
IS_ACK = 5
IS_NACK = 6
UN_USE = 0
OFFER = 1
USE = 2
FULL = -1
REFUSE = -1
ACK = 1

def getOfferIP(pool,data):
    want = getRequireIP(data)-1
    if pool[want]==UN_USE:
        return want
    else:
        for i in range(255):
            if pool[i] == UN_USE:
                return i
    return FULL

def check(pool,data):
    want = getRequireIP(data)-1
    if pool[want]==OFFER:
        return ACK
    else:
        return REFUSE

def getRequireIP(data):
    i = 240
    while i < len(data):
        if data[i:i+2] == b'\x32\x04':            
            return hexvalue(data[i+5:i+6])
        elif data[i] == b'\xff':
            return NOT_DHCP
        else:
            i += (2+hexvalue(data[i+1:i+2]))
    return NOT_DHCP

def printOption(data):
    i = 240
    while i < len(data):
        if data[i:i+1] == b'\x32':
            print('DHCP option 50: {}.{}.{}.{} requested'.format(hexvalue(data[i+2:i+3]),hexvalue(data[i+3:i+4]),hexvalue(data[i+4:i+5]),hexvalue(data[i+5:i+6])))
            i += 6
        elif data[i:i+1] == b'\x35':
            if getRequestType(data) == IS_DISCOVER:
                print('DHCP option 53: DHCP Discover')
            elif getRequestType(data) == IS_OFFER:
                print('DHCP option 53: DHCP Offer')
            elif getRequestType(data) == IS_REQUEST:
                print('DHCP option 53: DHCP Request')
            elif getRequestType(data) == IS_ACK:
                print('DHCP option 53: DHCP ACK')
            elif getRequestType(data) == IS_NACK:
                print('DHCP option 53: DHCP NAK')
            i += 3
        elif data[i:i+1] == b'\x33':
            print('DHCP option 51: {}s IP address lease time'.format(hexvalue(data[i+2:i+6])))
            i += 6
        elif data[i:i+1] == b'\x36':
            print('DHCP option 54: {}.{}.{}.{} DHCP server'.format(hexvalue(data[i+2:i+3]),hexvalue(data[i+3:i+4]),hexvalue(data[i+4:i+5]),hexvalue(data[i+5:i+6])))
            i += 6
        else:
            break

def printPacket(data):
    print('OP:{0:#0{4}x}\tHTYPE:{1:#0{4}x}\tHLEN:{2:#0{4}x}\tHOPS:{3:#0{4}x}'.format(hexvalue(data[0:1]),hexvalue(data[1:2]),hexvalue(data[2:3]),hexvalue(data[3:4]),4))
    print('XID:{0:#0{1}x}'.format(hexvalue(data[4:8]),10))
    print('SECS:{0:#0{2}x}\tFLAGS:{1:#0{2}x}'.format(hexvalue(data[8:10]),hexvalue(data[10:12]),6))
    print('CIADDR:{0:#0{1}x}'.format(hexvalue(data[12:16]),10))
    print('YIADDR:{0:#0{1}x}'.format(hexvalue(data[16:20]),10))
    print('SIADDR:{0:#0{1}x}'.format(hexvalue(data[20:24]),10))
    print('GIADDR:{0:#0{1}x}'.format(hexvalue(data[24:28]),10))
    print('CHADDR:{0:#0{4}x}\t{1:#0{4}x}\t{2:#0{4}x}\t{3:#0{4}x}'.format(hexvalue(data[28:32]),hexvalue(data[32:36]),hexvalue(data[36:40]),hexvalue(data[40:44]),10))
    print('Magic cookie:{0:#0{1}x}'.format(hexvalue(data[236:240]),10))
    printOption(data)
    
def hexvalue(data):
    return int(binascii.hexlify(data),16)
    
def getRequestType(data):    
    if data[236:240] != b'\x63\x82\x53\x63' :
        return NOT_DHCP
    i = 240
    while i < len(data):
        if data[i:i+2] == b'\x35\x01':
            return hexvalue(data[i+2:i+3])
        elif data[i] == b'\xff':
            return NOT_DHCP
        else:
            i += (2+hexvalue(data[i+1:i+2]))
    return NOT_DHCP

def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += pack('!B', m)
    return macb

class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += pack('!B', t)    

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #0:Message type: Boot Request (1)
        packet += b'\x01'   #1:Hardware type: Ethernet
        packet += b'\x06'   #2:Hardware address length: 6
        packet += b'\x00'   #3:Hops: 0 
        packet += self.transactionID       #4-7:Transaction ID
        packet += b'\x00\x00'    #8-9:Seconds elapsed: 0
        packet += b'\x00\x00'   #10-11:Bootp flags: 0x0000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #12-15:Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #16-19:Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #20-23:Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #24-27:Relay agent IP address: 0.0.0.0
        packet += macb  #28-33:hardware address
        packet += b'\x00' * 10  #34-43:Client hardware address padding
        packet += b'\x00' * 67  #44-110:Server host name not given
        packet += b'\x00' * 125 #111-235:Boot file name not given
        packet += b'\x63\x82\x53\x63'   #236-239:Magic cookie: DHCP
        #240-end: Option
        packet += b'\x35\x01\x01'   #240-242: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x32\x04\xc0\xa8\x01\x64'   #243-248: request address
        packet += b'\xff'   #249:End Option
        return packet

class DHCPOffer:
    def __init__(self,offer):        
        self.offerip = b''
        self.offerip += pack('!B', offer)

    def buildPacket(self,data):
        packet = b''
        packet += b'\x02'   #0:Message type: Boot Request (1)
        packet += b'\x01'   #1:Hardware type: Ethernet
        packet += b'\x06'   #2:Hardware address length: 6
        packet += b'\x00'   #3:Hops: 0 
        packet += data[4:8]       #4-7:Transaction ID
        packet += b'\x00\x00'    #8-9:Seconds elapsed: 0
        packet += b'\x00\x00'   #10-11:Bootp flags: 0x0000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #12-15:Client IP address: 0.0.0.0
        packet += (b'\xc0\xa8\x01'+self.offerip)   #16-19:Your (client) IP address: 0.0.0.0
        packet += b'\xc0\xa8\x01\x01'   #20-23:Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #24-27:Relay agent IP address: 0.0.0.0
        packet += data[28:34]  #28-33:hardware address
        packet += b'\x00' * 10  #34-43:Client hardware address padding
        packet += b'\x00' * 67  #44-110:Server host name not given
        packet += b'\x00' * 125 #111-235:Boot file name not given
        packet += b'\x63\x82\x53\x63'   #236-239:Magic cookie: DHCP
        #240-end: Option
        packet += b'\x35\x01\x02'   #240-242: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x33\x04\x00\x01\x51\x80'   #243-248: lease time
        packet += b'\x36\x04\xc0\xa8\x01\x01'   #249-254: server ip
        packet += b'\xff'   #255:End Option        
        return packet

class DHCPRequest:           
    def buildPacket(data):        
        packet = b''
        packet += b'\x01'   #0:Message type: Boot Request (1)
        packet += b'\x01'   #1:Hardware type: Ethernet
        packet += b'\x06'   #2:Hardware address length: 6
        packet += b'\x00'   #3:Hops: 0 
        packet += data[4:8]       #4-7:Transaction ID
        packet += b'\x00\x00'    #8-9:Seconds elapsed: 0
        packet += b'\x00\x00'   #10-11:Bootp flags: 0x0000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #12-15:Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #16-19:Your (client) IP address: 0.0.0.0
        packet += data[20:24]   #20-23:Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #24-27:Relay agent IP address: 0.0.0.0
        packet += data[28:34]  #28-33:hardware address
        packet += b'\x00' * 10  #34-43:Client hardware address padding
        packet += b'\x00' * 67  #44-110:Server host name not given
        packet += b'\x00' * 125 #111-235:Boot file name not given
        packet += b'\x63\x82\x53\x63'   #236-239:Magic cookie: DHCP
        #240-end: Option
        packet += b'\x35\x01\x03'   #240-242: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += (b'\x32\x04'+data[16:20])   #243-248: lease time
        packet += (b'\x36\x04'+data[20:24])   #249-254: server ip
        packet += b'\xff'   #255:End Option        
        return packet

class DHCPAck:
    def __init__(self,ip,check):        
        self.ackip = b''
        self.ackip += pack('!B', ip)
        self.check = check

    def buildPacket(self,data):
        packet = b''
        packet += b'\x02'   #0:Message type: Boot Request (1)
        packet += b'\x01'   #1:Hardware type: Ethernet
        packet += b'\x06'   #2:Hardware address length: 6
        packet += b'\x00'   #3:Hops: 0 
        packet += data[4:8]       #4-7:Transaction ID
        packet += b'\x00\x00'    #8-9:Seconds elapsed: 0
        packet += b'\x00\x00'   #10-11:Bootp flags: 0x0000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #12-15:Client IP address: 0.0.0.0
        packet += (b'\xc0\xa8\x01'+self.ackip)   #16-19:Your (client) IP address: 0.0.0.0
        packet += b'\xc0\xa8\x01\x01'   #20-23:Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #24-27:Relay agent IP address: 0.0.0.0
        packet += data[28:34]  #28-33:hardware address
        packet += b'\x00' * 10  #34-43:Client hardware address padding
        packet += b'\x00' * 67  #44-110:Server host name not given
        packet += b'\x00' * 125 #111-235:Boot file name not given
        packet += b'\x63\x82\x53\x63'   #236-239:Magic cookie: DHCP
        #240-end: Option
        if self.check == ACK:
            packet += b'\x35\x01\x05'   #240-242: (t=53,l=1) DHCP Message Type = DHCP Discover
        else:
            packet += b'\x35\x01\x06'   #240-242: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x33\x04\x00\x01\x51\x80'   #243-248: lease time
        packet += b'\x36\x04\xc0\xa8\x01\x01'   #249-254: server ip
        packet += b'\xff'   #255:End Option        
        return packet

def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('0.0.0.0', 67))
    offerip = []
    for i in range(255):
        offerip.append(UN_USE)
    offerip[0]=USE
    offerip[254]=USE
    while True:
        data, address = sock.recvfrom(MAX_BYTES)
        requestType = getRequestType(data)
        if requestType == IS_DISCOVER:
            print('A DHCPDiscover request recieved')
            offer = getOfferIP(offerip,data)
            if offer == FULL:
                continue
            offerPacket = DHCPOffer(offer+1)
            offerip[offer] = OFFER
            printPacket(data)
            sock.sendto(offerPacket.buildPacket(data), ('<broadcast>', 68))
        elif requestType == IS_REQUEST:
            print('A DHCPREQUEST request recieved')
            printPacket(data)
            ack = check(offerip,data)
            ip = getRequireIP(data)
            if ack == ACK:
                offerip[ip-1]=USE
            ackPacket = DHCPAck(ip,ack);
            sock.sendto(ackPacket.buildPacket(data), ('<broadcast>', 68))                
        else:
            print('An Unkenown request recieved')
            continue

def client():
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
    
    try:
        dhcps.bind(('', 68))    #we want to send from port 68
    except Exception as e:
        print('port 68 in use...')
        dhcps.close()
        input('press any key to quit...')
        exit()
        
    #buiding and sending the DHCPDiscover packet
    discoverPacket = DHCPDiscover()
    dhcps.sendto(discoverPacket.buildPacket(), ('<broadcast>', 67))
    
    print('DHCP Discover sent waiting for reply...\n')
    
    #receiving DHCPOffer packet  
    dhcps.settimeout(3)
    try:
        while True:
            data, address = dhcps.recvfrom(MAX_BYTES)
            if getRequestType(data)==IS_OFFER:
                print("An offer request recieved")
                printPacket(data)
                dhcps.sendto(DHCPRequest.buildPacket(data), ('<broadcast>', 67))
                while True:
                    data, address = dhcps.recvfrom(MAX_BYTES)
                    if getRequestType(data)==IS_ACK:
                        print("An ACK request recieved")
                        printPacket(data)
                        print('Now I can use IP: {}.{}.{}.{}'.format(hexvalue(data[16:17]),hexvalue(data[17:18]),hexvalue(data[18:19]),hexvalue(data[19:20])))
                        break
                    elif getRequestType(data)==IS_NACK:
                        print("An ACK request recieved")
                        printPacket(data)
                        print('IP: {}.{}.{}.{} is refused'.format(hexvalue(data[16:17]),hexvalue(data[17:18]),hexvalue(data[18:19]),hexvalue(data[19:20])))
                        break
                    else:
                        continue
            else:
                continue
    except socket.timeout as e:
        print(e)
    dhcps.close()   #we close the socket    
    input('press any key to quit...')
    exit()

if __name__ == '__main__':
    choices = {'client': client, 'server': server}
    parser = argparse.ArgumentParser(description='Send and receive UDP locally')
    parser.add_argument('role', choices=choices, help='which role to play')
    args = parser.parse_args()
    function = choices[args.role]
    function()
