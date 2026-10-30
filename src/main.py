
from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRSN,
    wrpcap
)

from scapy.layers.dot11 import AKMSuite


def build_beacon(ssid, ap_mac, channel_number):
    """
    Build and return one IEEE 802.11 Beacon frame.

    Parameters:
        ssid: Wi-Fi network name
        ap_mac: Access point MAC address
        channel_number: Wi-Fi channel
    """

    # Create the 802.11 management frame
    wifi_frame = Dot11(
        type=0,
        subtype=8,
        addr1="FF:FF:FF:FF:FF:FF",
        addr2=ap_mac,
        addr3=ap_mac
    )

    # Configure Beacon capabilities
    beacon = Dot11Beacon(
        cap="ESS+privacy+short-preamble"
    )

    # IE 0: SSID
    ssid_element = Dot11Elt(
        ID=0,
        info=ssid.encode("utf-8")
    )

    # IE 1: Supported Rates
    supported_rates = Dot11Elt(
        ID=1,
        info=bytes([0x82, 0x84, 0x8B, 0x96])
    )

    # IE 3: DS Parameter Set (channel)
    channel = Dot11Elt(
        ID=3,
        info=bytes([channel_number])
    )

    # IE 48: RSN security information
    rsn = Dot11EltRSN(
        akm_suites=[AKMSuite(suite=2)],
        mfp_capable=0,
        mfp_required=0
    )

    # Combine all packet layers
    packet = (
        wifi_frame
        / beacon
        / ssid_element
        / supported_rates
        / channel
        / rsn
    )

    # Return the completed packet
    return packet


def main():

    # Create Beacon frames for three example access points
    beacon_1 = build_beacon(
        "Training_WiFi",
        "AA:BB:CC:DD:EE:FF",
        6
    )

    beacon_2 = build_beacon(
        "Office_WiFi",
        "11:22:33:44:55:66",
        11
    )

    beacon_3 = build_beacon(
        "Guest_WiFi",
        "22:33:44:55:66:77",
        1
    )

    # Store all Beacon packets in a list
    packets = [
        beacon_1,
        beacon_2,
        beacon_3,
        beacon_1
    ]

    # Save all three packets into one PCAP file
    wrpcap("samples/beacon_sample.pcap", packets)

    print("Multiple Beacon frames generated successfully!")
    print("Total Beacon frames:", len(packets))
    print("Capture saved to samples/beacon_sample.pcap")


if __name__ == "__main__":
    main()
