# Import Scapy tools for Wi-Fi frame construction
from scapy.all import Dot11, Dot11Beacon, Dot11Elt


def main():

    # Define an example access point MAC address
    ap_mac = "AA:BB:CC:DD:EE:FF"

    # Create the 802.11 MAC header
    wifi_frame = Dot11(
        type=0,
        subtype=8,
        addr1="FF:FF:FF:FF:FF:FF",
        addr2=ap_mac,
        addr3=ap_mac
    )

    # Add the Beacon management frame
    beacon = Dot11Beacon()

    # Add the Wi-Fi network name (SSID)
    ssid = Dot11Elt(
        ID=0,
        info=b"Training_WiFi"
    )

    # Combine all layers
    packet = wifi_frame / beacon / ssid

    # Display a short summary
    print("802.11 Beacon Frame:")
    print(packet.summary())

    # Display detailed information
    packet.show()


if __name__ == "__main__":
    main()