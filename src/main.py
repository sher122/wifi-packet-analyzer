# Import Scapy's packet-building tools
from scapy.all import Ether, IP, ICMP


def main():

    # Create an artificial Ethernet packet
    packet = Ether()

    # Add an IP layer
    packet = packet / IP(dst="8.8.8.8")

    # Add an ICMP layer
    packet = packet / ICMP()

    # Display the packet summary
    print("Our first packet:")
    print(packet.summary())

    # Display detailed packet information
    print("\nDetailed packet information:")
    packet.show()


# Start the program
if __name__ == "__main__":
    main()