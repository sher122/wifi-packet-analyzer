from scapy.all import (
    rdpcap,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltDSSSet,
    Dot11EltRSN
)


def main():
    # Read packets from our sample capture
    packets = rdpcap("samples/beacon_sample.pcap")

    print("Total packets captured:", len(packets))

    # Convert IEEE suite identifiers into readable names
    cipher_names = {
        4: "CCMP-128"
    }

    akm_names = {
        1: "802.1X",
        2: "PSK"
    }

    # Examine each packet
    for packet in packets:

        # Process only Beacon frames
        if packet.haslayer(Dot11Beacon):

            print("\nBeacon frame detected!")

            # Extract BSSID
            bssid = packet[Dot11].addr3
            print("BSSID:", bssid)

            # Find the SSID information element (ID 0)
            ssid = None
            element = packet.getlayer(Dot11Elt)

            while isinstance(element, Dot11Elt):

                if element.ID == 0:
                    ssid = element.info.decode(
                        "utf-8",
                        errors="replace"
                    )
                    break

                # Move to the next information element
                element = element.payload

            # Handle a missing SSID element
            if ssid is None:
                ssid = "<SSID not found>"
            elif ssid == "":
                ssid = "<Hidden SSID>"

            print("SSID:", ssid)

            # Extract channel
            if packet.haslayer(Dot11EltDSSSet):
                channel = packet[Dot11EltDSSSet].channel
                print("Channel:", channel)

            # Extract RSN security information
            if packet.haslayer(Dot11EltRSN):

                rsn = packet[Dot11EltRSN]

                group_value = rsn.group_cipher_suite.cipher
                pairwise_value = rsn.pairwise_cipher_suites[0].cipher
                akm_value = rsn.akm_suites[0].suite

                group_cipher = cipher_names.get(
                    group_value, f"Unknown ({group_value})"
                )

                pairwise_cipher = cipher_names.get(
                    pairwise_value, f"Unknown ({pairwise_value})"
                )

                authentication = akm_names.get(
                    akm_value, f"Unknown ({akm_value})"
                )

                print("Group Cipher:", group_cipher)
                print("Pairwise Cipher:", pairwise_cipher)
                print("Authentication:", authentication)


if __name__ == "__main__":
    main()