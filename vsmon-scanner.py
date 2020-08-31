import socket
import time
import ifaddr
import uuid
import argparse
import traceback

import xml.etree.ElementTree as ET

from thread import *
import threading


'''
Msvsmon stores the list of probes' UUIDs and replies a prbobe only once.
So we need to regenerate the UUID for every probe. 
'''
PROBE1 = r'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dp0="http://www.microsoft.com/visualstudio/debugger/discovery/16.0"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:'

#b020e78c-1688-4d27-affc-578956a15f7a

PROBE2 = '</wsa:MessageID></soap:Header><soap:Body><wsd:Probe><wsd:Types>dp0:msvsmon</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>'

DEBUG = False
SSDP_BROADCAST = '239.255.255.250' #well-known multicast IPv4 address for SSDP discovery
SSDP_PORT = 3702
NUM_OF_PROBES = 7 #For some reasons VS sends 7 probes
BIND_PORT_START = 60770 #Initial port binding address


def trace(content):
    if DEBUG == True:
        print "{0}\n".format(content),
        
def safer_print(content):        
    print "{0}\n".format(content),

'''
Runs in a dedicated thread
Sends XML probe to the destination IP
'''
def threaded(ip_bind, port_bind, ip_dst):
    
    try:
        safer_print('Sending probe to {}:{}, bound to {}, thread: {}'.format(ip_dst, str(port_bind), ip_bind, get_ident()))
        sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock4.bind((ip_bind, port_bind))
        
        probe = PROBE1
        probe = probe + str(uuid.uuid4())
        probe = probe + PROBE2
        for i in range(0, NUM_OF_PROBES):
            sent4 = sock4.sendto(probe, (ip_dst, SSDP_PORT))
            time.sleep(1)
        sock4.settimeout(5.0)
        data, sender_addr = sock4.recvfrom(2048)
        sock4.settimeout(None)
        root = ET.fromstring(data)
        for child in root.iter('*'):
            if child.tag.find('MsvsmonInstance') != -1:
                safer_print('MsvsmonInstance found:')
                for key in child.attrib:
                    brace = key.find('}')
                    if brace != -1:
                        aname = key[brace + 1:]
                    safer_print('{} : {}'.format(aname, child.attrib[key]))
        safer_print('from {}:{}'.format(sender_addr[0], sender_addr[1]))
    except Exception:
        safer_print('Exception in thread: {}'.format(get_ident()))
        trace(traceback.format_exc())

'''
Iterates over all network adapters, binds to every adapter and sends XML probe to SSDP_BROADCAST
'''
def broadcast():
    port = BIND_PORT_START
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        trace("IPs of network adapter " + adapter.nice_name)
        for ip in adapter.ips:    
            if (type(ip.ip) is str):
                if (ip.ip == '127.0.0.1'):
                    continue
                trace('Starting thread for ' + ip.ip)
                start_new_thread(threaded, (ip.ip, port, SSDP_BROADCAST))
        port = port + 1

'''
If binding IP specified bind to the IP, otherwise bind to all adapters.
If destination IP specified, send the probe to the IP, otherwise broadcast the probe.
'''
def main(ip_bind, ip_dst):
    while True:
        port = BIND_PORT_START
        if (ip_bind != None):
            if (ip_dst != None):
                start_new_thread(threaded, (ip_bind, port, ip_dst))
            else:
                start_new_thread(threaded, (ip_bind, port, SSDP_BROADCAST))
        else:
            broadcast()
        time.sleep(20)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Scan Msvsmon instances')
    parser.add_argument('--ip_dst', metavar='ip_dst', required=False,
                        help='IP address [optional, broadcast if not given]')
    parser.add_argument('--ip_bind', metavar='ip_bind', required=False,
                        help='IP address of the adapter to bind [optional, broadcast if not given]')                        
    args = parser.parse_args()
    
    main(args.ip_bind, args.ip_dst)