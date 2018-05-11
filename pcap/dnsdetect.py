import argparse
from scapy.all import *
from collections import deque
import datetime

packet_queue = deque(maxlen = 100)
flow_map = {}

def dns_detect(packet):
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):
        if len(packet_queue)>0:
            for op in packet_queue:
                if op[IP].dst == packet[IP].dst:
                    if op[IP].sport == packet[IP].sport:
                        if op[IP].dport == packet[IP].dport:
                            if op[DNSRR].rdata != packet[DNSRR].rdata:
                                if op[DNS].id == packet[DNS].id:
                                    if op[DNS].qd.qname == packet[DNS].qd.qname:
                                        if op[IP].payload != packet[IP].payload:
                                            print(str(datetime.datetime.now())+ "  DNS poisoning attempt")
                                            print("TXID %s Request URL %s"%( op[DNS].id, op[DNS].qd.qname.decode('utf-8').rstrip('.')))
                                            print("Answer1 [%s]"%op[DNSRR].rdata)
                                            print("Answer2 [%s]"%packet[DNSRR].rdata)
        packet_queue.append(packet)

def dns_detect_flow(packet):
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):

        print("Detect FLow")
        new_packet = {
            'dst'  : repr(packet[IP].dst),
            'sport': repr(packet[IP].sport),
            'dport': repr(packet[IP].dport),
            'tx_id': repr(packet[DNS].id),
            'q_url': repr(packet[DNS].qd.qname),
            'rdata': repr(packet[DNSRR].rdata)
        }

        packet_queue.append(new_packet)

def get_tcp_packet_dict(packet):
    packet_dict = {
        'src'  : repr(packet[IP].src),
        'dst'  : repr(packet[IP].dst),
        'sport': repr(packet[IP].sport),
        'dport': repr(packet[IP].dport),
        'flags': repr(packet[TCP].flags),
        'size' : repr(len(packet))
    }
    return packet_dict

def dns_detect_tcp_flow(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        flow_key_1 = repr(packet[IP].sport) + repr(packet[IP].dport)
        flow_key_2 = repr(packet[IP].dport) + repr(packet[IP].sport)


        if flow_key_1 in flow_map or flow_key_2 in flow_map:
            
            if flow_key_1 in flow_map:
                flow_map[flow_key_1].append(get_tcp_packet_dict(packet))
            
            if flow_key_2 in flow_map:
                flow_map[flow_key_2].append(get_tcp_packet_dict(packet))

        else:
            flow_map[flow_key_1] = [get_tcp_packet_dict(packet)]

def send_flows_to_scheduler(flow_map):
    for flow in flow_map:
        flow_size = 0
        for packet in flow_map[flow]:
            flow_size += int(packet['size'])
        print("Flow Size: {}".format(flow_size))

def parse_input_args():
    arg_parser = argparse.ArgumentParser(add_help=False)
    arg_parser.add_argument("-i", metavar="listening_interface")
    arg_parser.add_argument("-r", metavar = "pcap_file")
    arg_parser.add_argument('expression', nargs='*',action="store")
    args = arg_parser.parse_args()

    return args.i, args.r, args.expression

def parse_expression(expression_list):
    exp_str = ''
    for exp in expression_list:
        exp_str += exp + ' '
    return exp_str.strip()

if __name__ == '__main__':
    interface, pcap_file, expression= parse_input_args()
    filter_expression = ' '.join(expression)
    if len(expression) == 0:
            if interface != None:
                sniff(iface=interface, store=0, prn=dns_detect)
            elif pcap_file != None:
                sniff(offline = pcap_file, store=0, prn=dns_detect)
                send_flows_to_scheduler(flow_map)
            else:
                default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
                sniff(iface = default_interface, store=0, prn=dns_detect)
    else:
            expression = ' '.join(expression)
            if interface != None:
                sniff(filter=expression, iface=interface, store=0, prn=dns_detect)
            elif pcap_file != None:
                sniff(filter=expression, offline = pcap_file, store=0, prn=dns_detect)
            else:
                sniff(filter=expression, store=0, prn=dns_detect)
