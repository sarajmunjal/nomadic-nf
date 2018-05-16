import argparse
from scapy.all import *
from collections import deque
import datetime
import numpy as np
import time
import requests

start_time = time.time();
URL = "http://35.224.66.131/packet"
count =  0
tot_lat = 0
lats = []
tot_size = 0
def dns_listen(packet):
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):

        dns_packet = {
            "dst"  : packet[IP].dst,
            "sport": packet[IP].sport,
            "dport": packet[IP].dport,
            "tx_id": packet[DNS].id,
            "q_url": packet[DNS].qd.qname.decode('utf-8'),
            "rdata": packet[DNSRR].rdata
        }

        if isinstance(dns_packet['rdata'], bytes):
            dns_packet['rdata'] = dns_packet['rdata'].decode('utf-8')


        #print("DNS PACKET: {}".format(type(dns_packet['rdata'])))

        DNS_URL = "http://35.224.66.131:5001/dnstest"
        #req = requests.post(DNS_URL, json=dns_packet)
    #make request

def packet_listen(packet):
    global lets
    global start_time
    global tot_size
    if packet.haslayer(IP) and packet.haslayer(TCP):
        packet_dict = {
            'src'  : packet[IP].src,
            'dst'  : packet[IP].dst,
            'sport': str(packet[IP].sport),
            'dport': str(packet[IP].dport),
            'size' : str(len(packet))
        }

        PACKET_URL = "http://35.224.66.131/flow"
        URL = "http://35.224.66.131/test"
        res = requests.post(PACKET_URL, json=packet_dict)
        # count+=1
        lats.append(res.elapsed.total_seconds() * 1000)
        tot_size+=len(packet)
        if len(lats) % 100 == 0:
            np_lats = np.array(lats)
            tail_lat = np.percentile(np_lats, 99)
            print("Tot_Lat: {}, 99_lat:{}, count:{}, time: {}, size:{}".format(np.sum(np_lats), tail_lat, len(lats), time.time() - start_time, tot_size))

def parse_input_args():
    arg_parser = argparse.ArgumentParser(add_help=False)
    arg_parser.add_argument("-i", metavar="listening_interface")
    arg_parser.add_argument("-r", metavar = "pcap_file")
    arg_parser.add_argument('-m', metavar='mode')
    args = arg_parser.parse_args()

    return args.i, args.r, args.m

def parse_expression(expression_list):
    exp_str = ''
    for exp in expression_list:
        exp_str += exp + ' '
    return exp_str.strip()
count_packet = 0
if __name__ == '__main__':
    interface, pcap_file, mode= parse_input_args()

    if mode == 'dns':
        if interface != None:
            sniff(iface=interface, store=0, prn=dns_listen)
        elif pcap_file != None:
            sniff(offline = pcap_file, store=0, prn=dns_listen)
        else:
            default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            sniff(iface = default_interface, store=0, prn=dns_listen)
    else:
        if interface != None:
            sniff(iface=interface, store=0, prn=packet_listen)
        elif pcap_file != None:
            sniff(offline = pcap_file, store=0, prn=packet_listen)
    np_lats = np.array(lats)
    tail_lat = np.percentile(np_lats, 99)
    print("Tot_Lat: {}, 99_lat:{}, count:{}".format(np.sum(np_lats), tail_lat, len(lats)))
