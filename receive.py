from scapy.all import *

def packet_handler(packet):
    # Print the packet summary
    print(packet.summary())

def main(interface):
    # Sniff packets on the specified interface
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)
    interface = sys.argv[1]
    main(interface)
