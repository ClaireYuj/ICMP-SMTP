# -*- coding = utf-8 -*-
# @Time : 2021/10/9 15:27
# @Author:Yu
# @File: Traceroute.py
# @Software: PyCharm

import socket
import random
import re
import os
import sys
import struct
import time
import select
import binascii
from scapy.all import *

ICMP_ECHO_REUEST = 8
ECHO_REQUEST_DEFAULT = 0
TTL_OVERTIME = 0

ICMP_ECHO_REPLY = 0
ICMP_UNREACHED = 3
ICMP_ECHO = 8
ICMP_OVERTIME = 11

UDP_PORT = 33434
MAX_HOP = 30
COLUMN = 3
ICMP_MIN = 8


def get_checksum(string):
    """
      return the checksum of source
    the sum of 16-bit binary one's complement
    :param string:
    :return:
    """
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    answer = socket.htons(answer)

    return answer

def createICMPPacket():
    """
    create a icmp packet
    :return:
    """

    id = os.getpid() & 0xFFFF
    checksum = 0
    seq = 1
    header = struct.pack(">BBHHH", ICMP_ECHO_REUEST, ECHO_REQUEST_DEFAULT, checksum, id, seq)
    data = struct.pack(">d", time.time())
    packet = header+data
    checksum = get_checksum(packet)
    header = struct.pack(">BBHHH", ICMP_ECHO_REUEST, ECHO_REQUEST_DEFAULT, socket.htons((checksum)), id, seq) # type code checksum id seq
    packet = header+data
    return packet

def tracerouteIcmp(hostname):
    """
    do the traceroute in icmp way
    :param hostname:
    :return:
    """
    # get the ip address by hostname
    try:
        destAddress=socket.gethostbyname(hostname)
    except Exception as e:
        return
    ttl = 1
    print("routing from {0} {1} max hops = {2}".format(hostname, destAddress, MAX_HOP))
    for ttl in range(1, MAX_HOP):
        print("%2d" % ttl, end="")
        for tries in range(0, COLUMN):
            #create raw socket
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl)) # I - long
            icmpSocket.settimeout(TIMEOUT)

            #create packet
            icmpPacket = createICMPPacket()
            icmpSocket.sendto(icmpPacket, (hostname, 0))

            #get the during time
            sendtime = time.time()
            select.select([icmpSocket], [], [], 1)
            revTime = time.time()
            duringtime = revTime - sendtime

            if duringtime < TIMEOUT and duringtime != 0 and duringtime < 1:
                print(" %4.0f ms " % (duringtime * 1000), end="")
            else:
                print("   *   ", end="")

            #when the hop is less than the settled column, continue to jump to next node
            if tries >= COLUMN-1:
                try:
                    revPacket, addr = icmpSocket.recvfrom(1024)
                except socket.timeout as e:
                    print("request time out")
                else:
                    icmpHeader = revPacket[20:28]
                    #extract header
                    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack(">BBHHH", icmpHeader)

                    #get the ip information

                    try:
                        ip_name = socket.gethostbyaddr(addr[0])
                    except Exception as e:
                        result = '{0}'.format(addr[0])
                    else:
                        result = '{0} ({1})'.format(addr[0], ip_name[0])

                    #judge the icmp type and do the reactions
                    if icmp_type == ICMP_OVERTIME: #overtime
                        print(" %s " % result)
                        continue
                    elif icmp_type == ICMP_UNREACHED: #unreached exception
                        print(" unreached host!")
                        break
                    elif icmp_type == ICMP_ECHO_REPLY: #the last hop
                        print(" %s " % result, end="")
                        print("\n---end---", end="")
                        return
                    else:
                        print("request time out", end="")
                        print("\n---end---")
                        return

def tracerouteOnceUDP(dst,_ttl,port):
    """
    send a udp packet and then get a icmp reply
    analyze the type in icmp header and return different return value
    :param dst:
    :param _ttl:
    :param port:
    :return:
    """

    sendTime = time.time()
    try:
        # send a udp packet to destinationAddress and receive a icmp reply( use scapy -- a simpler way) create a fake packet
        udpReply = sr1(IP(dst=dst, ttl=_ttl) / UDP(dport=port) /b'1111', timeout=1,
                                   verbose=False)
        #if the icmp reply is 11--the overtime reply, which means do not achieve the destination
        if udpReply.getlayer(ICMP).type == ICMP_OVERTIME and udpReply.getlayer(ICMP).code == ICMP_ECHO_REPLY:
            routeIp = udpReply.getlayer(IP).src
            revTime = time.time()
            duringTime = (revTime - sendTime) *1000
            return 1, routeIp, duringTime
        # if the icmp reply is icmp unreached(3), which means we have reach the destination, return a identifier 0 and the hop ip and the during_time
        elif udpReply.getlayer(ICMP).type == ICMP_UNREACHED and udpReply.getlayer(ICMP).code == ICMP_UNREACHED:
            routeIp = udpReply.getlayer(IP).src
            revTime = time.time()
            duringTime = (revTime - sendTime) * 1000
            return 2, routeIp, duringTime
    except Exception as e:
        return None

def tracerouteUDP(hostname, maxhop):
    """
    udp traceroute method
    :param hostname:
    :param maxhop:
    :return:
    """
    dport = UDP_PORT
    hop = 0
    dst = socket.gethostbyname(hostname)
    print("routing from {0} {1} max hops = {2}".format(hostname, dst, maxhop))
    # get the ip address by hostname
    while hop < maxhop:
        hop += 1
        # change the port number!
        dport += hop
        # send a packet
        Result= tracerouteOnceUDP(dst, hop, dport)
        # print * if there are exceptions
        if Result == None:  # which means fail to get the result
            print(str(hop) + '  *  ', flush=True)
        # do not achieve the destination, print the time
        elif Result[0] == 1:
            time_to_pass_result = '%4.2f' % Result[2]
            print(str(hop) + ' ' + str(Result[1]) + '    ' + time_to_pass_result + 'ms')
        # acheieve the destination and jump over the loop
        elif Result[0] == 2:
            time_to_pass_result = '%4.2f' % Result[2]
            print(str(hop) + ' ' + str(Result[1]) + '    ' + time_to_pass_result + 'ms')
            break
        time.sleep(1)


if __name__ == "__main__":

    ip = input("please input the hostname:")

    global TIMEOUT 
    TIMEOUT = int(input("please set the timeout:"))
    protocal = input("please choose the udp/icmp(in lowercase):")
    if protocal =="icmp":
        tracerouteIcmp(ip)
    elif protocal =="udp":
        # maxhop = int(input("please input the maxhop:"))
        maxhop = 20
        tracerouteUDP(ip, maxhop)
    else:
        print("ERROR!please input the correct format of protocal!")
