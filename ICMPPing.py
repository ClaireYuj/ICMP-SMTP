#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# @Time : 2021/10/2 10:37
# @Author:Yu
# @File: ICMPPing.py
# @Software: PyCharm

import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8  # ICMP type code for echo request messages
ICMP_ECHO_REPLY = 0  # ICMP type code for echo reply messages
ICMP_UNREACHED =3
ICMP_OVERTIME = 11

def checksum(string):
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


def receiveOnePing(icmpSocket, destinationAddress, ID, timeout, startTime):
    """
    wait the socket to receive the reply by select.select, calculate the time to receive the packet

    :param icmpSocket:
    :param destinationAddress:
    :param ID:
    :param timeout:
    :param startTime:
    :return delay, ttl:
    """
    # 1. Wait for the socket to receive a reply
    while True:
        what_ready = select.select([icmpSocket], [], [], timeout)
        receivedTime = time.time()
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        if what_ready[0] == []:
            return -1, 0
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        else:
            delay = receivedTime - startTime

        # 4. Unpack the packet header for useful information, including the ID
        recPacket, addr = icmpSocket.recvfrom(1024)
        icmpHeader = recPacket[20: 28]
        # ip_type, code, checksum, packet_ID, sequence = struct.unpack("<bbHHh", icmpHeader)
        icmpType, icmpCode, icmpChecksum, icmpPacketID, icmpSequence = struct.unpack(">BBHHH", icmpHeader)

        ipversion, iptype, iplength, ipid, ipflags, ipttl, ipprotocol, ipchecksum, ipsrc_ip, ipdest_ip = struct.unpack(
            "!BBHHHBBHII", recPacket[:20])
        # 5. Check that the ID matches between the request and reply
        if icmpType == ICMP_ECHO_REPLY and icmpPacketID == ID:

            # 6. Return total network delay
            return delay, ipttl
        elif icmpType == ICMP_UNREACHED:
            return -3, 0
        elif icmpType == ICMP_OVERTIME:
            return -11, 0
        else:
            return -2, 0




def sendOnePing(icmpSocket, destinationAddress, ID):
    """
    build the icmp header, and pack the checksum in header
    record the time to send packet
    :param icmpSocket:
    :param destinationAddress:
    :param ID:
    :return icmpPacket, sendTime:
    """
    # 1. Build ICMP header
    ip = socket.gethostbyname(destinationAddress)
    icmpChecksum = 0
    icmpHeader = struct.pack(">BBHHH", ICMP_ECHO_REQUEST, 0, socket.htons(icmpChecksum), ID, 1) #htons - trans the byte sequence of host nto network byte order

    # 2. Checksum ICMP packet using given function
    data = struct.pack(">d", time.time())
    icmpChecksum = checksum(icmpHeader + data)

    # 3. Insert checksum into packet
    # icmpHeader = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(icmpChecksum), ID, 1)
    icmpHeader = struct.pack(">BBHHH", ICMP_ECHO_REQUEST, 0, socket.htons(icmpChecksum), ID, 1) # B-unsigned char h -short
    icmpPacket = icmpHeader + data


    # 4. Send packet using socket
    icmpSocket.sendto(icmpPacket, (ip, 80))

    #  5. Record time of sending
    sendTime = time.time()
    return icmpPacket, sendTime


def doOnePing(destinationAddress, timeout):
    """
    create the ICMP socket, then call the sendOnePing and receiveOnePing method in sequence
    :param destinationAddress:
    :param timeout:
    :return totalDelay, ttl:
    """
    # 1. Create ICMP socket
    icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    dataID = os.getpid() & 0xFFFF

    # 2. Call sendOnePing function
    icmpPacket, sendtime = sendOnePing(icmpSocket, destinationAddress, dataID)

    # 3. Call receiveOnePing function
    totalDelay, ttl = receiveOnePing(icmpSocket, destinationAddress, dataID, timeout, sendtime)
    # 4. Close ICMP socket
    icmpSocket.close()

    # 5. Return total network delay
    return totalDelay, ttl


def ping(host, timeout=1):
    """
    do the ping use doOnePing method in a while loop, and show the details
    :param host:
    :param timeout:
    :return:
    """
    # 1. Look up hostname, resolving it to an IP address
    # 2. Call doOnePing function, approximately every second
    # 3. Print out the returned delay
    # 4. Continue this process until stopped
    try:
        destinationAddress = socket.gethostbyname(host)
    except Exception as e:
        print(e)
        print(" Error on extract the hostname")
        return
    print(" Ping {0} [{1}] with 32 bytes of data:".format(host, destinationAddress))
    lost = 0
    accept = 0
    timesum = 0.0
    count = 4
    times = []
    ttl = 0

    for i in range(count):

        sequence = i
        delay, ttl = doOnePing(destinationAddress, timeout)
        if delay < 0:
            if delay == -1:
                print(" %s The request is overtime ...... can not receive the icmpPacket " % delay)
                lost += 1
                times.append(delay * 1000)
            elif delay == -3:
                print("3 The destination is unreachable")
            elif delay == -11:
                print("11 Overtime")
            else:
                print("%s failed......." %delay)

        else:
            delay = delay * 1000
            print("reply from {0} : byte=32 seq = {1} time={2:.2f}ms ttl = {3} ".format(destinationAddress, sequence, delay, ttl))
            accept += 1
            timesum += delay
            times.append(delay) # all the time
        time.sleep(1)
    print('packet: send = {0}，received = {1}，loss= {2} ({3}% loss) \n\
	Estimated round trip time: min = {4:.2f}ms，max = {5:.2f}ms，average = {6:.2f}ms'.format(
        count, accept, lost, lost / (lost + accept) * 100, min(times),
        max(times), sum(times) // (lost + accept)
    ))

if __name__ == '__main__':
    hostname = input("please input the ip address/hostname you want to ping from:")
    ping(hostname)
