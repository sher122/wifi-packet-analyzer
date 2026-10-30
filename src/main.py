
from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRSN,
    wrpcap
)

from scapy.layers.dot11 import AKMSuite


def main():

    # MAC address of our example access point
    ap_mac = "AA:BB:CC:DD:EE:FF"

    # Create an 802.11 management Beacon frame
    wifi_frame = Dot11(
        type=0,
        subtype=8,
        addr1="FF:FF:FF:FF:FF:FF",
        addr2=ap_mac,
        addr3=ap_mac
    )

    # Create the Beacon information
    beacon = Dot11Beacon(
        cap="ESS+privacy+short-preamble"
    )
    # IE 0: SSID (Element ID 0)
    ssid = Dot11Elt(
        ID=0,
        info=b"Training_WiFi"
    )
    # IE 1: Supported Rates (Element ID 1)
    supported_rates = Dot11Elt(
        ID=1,
        info=bytes([0x82, 0x84, 0x8B, 0x96])
    )

    # IE 2: DS Parameter Set (Element ID 3)
    channel = Dot11Elt(
        ID=3,
        info=bytes([6])
    )

    # IE 3: RSN (Element ID 48)
    # Example WPA2-Personal security configuration
    rsn = Dot11EltRSN(
        akm_suites=[AKMSuite(suite=2)],
        mfp_capable=0,
        mfp_required=0
    )

    # Combine the layers into a Beacon frame.
    # Notice that we intentionally omit the SSID element.
    ssid = Dot11Elt(
    ID=0,
    info=b"Training_WiFi"
)
    packet = (
        wifi_frame
        / beacon
        / ssid
        / supported_rates
        / channel
        / rsn
    )

    # Display a short packet summary
    print("802.11 Beacon Frame:")
    print(packet.summary())

    # Display Frame Control information
    print("\nFrame Control information:")
    print("Type:", packet.type)
    print("Subtype:", packet.subtype)

    # Convert Scapy's flags into an integer
    fc_flags = int(packet.FCfield)

    print("To DS:", fc_flags & 0x01)
    print("From DS:", fc_flags & 0x02)
    print("Retry:", bool(fc_flags & 0x08))
    print("Protected:", bool(fc_flags & 0x40))

    # Display the first two serialized Frame Control bytes
    raw_packet = bytes(packet)
    print("Frame Control bytes:", raw_packet[:2].hex())

    # Display detailed Beacon information
    print("\nDetailed Beacon Information:")
    packet.show2()

    # Display serialized packet length
    print("\nSerialized packet length:")
    print(len(bytes(packet)), "bytes")

    # Save the Beacon into a PCAP file
    wrpcap("samples/beacon_sample.pcap", packet)

    print("\nBeacon saved to samples/beacon_sample.pcap")


if __name__ == "__main__":
    main()
