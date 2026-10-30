from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11EltRSN
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
    # Configure Beacon capability flags
    beacon = Dot11Beacon(
    cap="ESS+privacy+short-preamble"
)

    # IE 1: SSID (Element ID 0)
    ssid = Dot11Elt(
        ID=0,
        info=b"Training_WiFi"
    )

    # IE 2: Supported Rates (Element ID 1)
    supported_rates = Dot11Elt(
        ID=1,
        info=bytes([0x82, 0x84, 0x8B, 0x96])
    )

    # IE 3: DS Parameter Set (Element ID 3)
    channel = Dot11Elt(
        ID=3,
        info=bytes([6])
    )

    # IE 4: RSN (Element ID 48)
    # Example WPA2-Personal security configuration
    rsn = Dot11EltRSN(
        akm_suites=[AKMSuite(suite=2)],  # PSK authentication
        mfp_capable=0,
        mfp_required=0
    )

    # Combine all layers and Information Elements
    # Important: All layers must be created before combining them.
    packet = (
        wifi_frame
        / beacon
        / ssid
        / supported_rates
        / channel
        / rsn
    )

    print("802.11 Beacon Frame:")
    print(packet.summary())
        # Display the Frame Control field
    print("\nFrame Control information:")
    print("Type:", packet.type)
    print("Subtype:", packet.subtype)
    # Convert Scapy's flag value into an integer
    fc_flags = int(packet.FCfield)
    # Check individual Frame Control flags
    print("To DS:", fc_flags & 0x01)
    print("From DS:", fc_flags & 0x02)
    # Check Retry and Protected Frame flags
    print("Retry:", bool(fc_flags & 0x08))
    print("Protected:", bool(fc_flags & 0x40))

    # Display the raw first two bytes
    raw_packet = bytes(packet)
    print("Frame Control bytes:", raw_packet[:2].hex())

    print("\nDetailed Beacon Information:")
    packet.show2()

    print("\nSerialized packet length:")
    print(len(bytes(packet)), "bytes")


if __name__ == "__main__":
    main()
