from scapy.all import *
import sys, getopt
import netifaces
import requests
import time
millis = int(round(time.time() * 1000))
sessionName = 'SESSION_' + str(millis)
URL = 'https://us-central1-stable-house-183720.cloudfunctions.net/pktCtr?sessionName=' +sessionName;
def callback():
    def process(pkt):
        print('Pkt!')
        try:
            requests.get(URL, timeout=10)
        except Exception as e:
            print("Error occurred: " + str(e));
            sys.exit(0)

    return process



def get_local_ip(interface_name):
    return netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['addr'].encode("UTF-8")


def parse_args(argv):
    hosts_file = ''
    interface_name = ''
    try:
        opts, args = getopt.getopt(argv, "r:i:")
    except getopt.GetoptError:
        print('Incorrect format of args. Expected: python dnsdetect.py [-i interface] [-r tracefile] expression')
        sys.exit(2)
    l = len(args)
    if l > 1:
        print('Too many arguments.  Expected: python dnsdetect.py [-i interface] [-r tracefile] expression')
        sys.exit(2)
    if l < 1:
        print('Too few arguments.  Expected: python dnsdetect.py [-i interface] [-r tracefile] expression')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-r':
            hosts_file = arg
        elif opt == "-i":
            interface_name = arg

    return hosts_file, interface_name, args[0]


def get_fallback_default_interface():
    return netifaces.interfaces()[0]


def get_default_interface():
    gateways = netifaces.gateways()
    if not gateways:
        return get_fallback_default_interface()
    def_gateway = gateways['default']
    if not def_gateway:
        return get_fallback_default_interface()
    return def_gateway[netifaces.AF_INET][1]


def main(argv):
    map = {}
    # interface = get_default_interface() if interface_name is '' else interface_name
    interface = get_default_interface()
    local_ip = get_local_ip(interface)
    # bpf_filt = 'udp src port 53 && ip dst {0}'.format(local_ip) if (bpf_expr is '') else bpf_expr
    print('Sniffing session: ' + str(sessionName))
    sniff(iface=interface, prn=callback())
    # else:
    #     sniff(offline=trace_file, iface=interface, filter=bpf_filt, prn=callback(map, local_ip))


if __name__ == "__main__":
    main(sys.argv[1:])