import csv
from scapy.all import (
    rdpcap,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltDSSSet,
    Dot11EltRSN
)


def export_to_csv(networks):

    # Define the output CSV file
    output_file = "reports/wifi_networks.csv"

    # Define CSV column names
    fieldnames = [
        "SSID",
        "BSSID",
        "Channel",
        "Security"
    ]

    # Write network information into the CSV file
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        # Write the column headings
        writer.writeheader()

        # Write each network record
        for network in networks:

            writer.writerow({
                "SSID": network["ssid"],
                "BSSID": network["bssid"],
                "Channel": network["channel"],
                "Security": network["security"]
            })

    print("\nCSV report generated:", output_file)


def main():

    # Read packets from the sample capture
    packets = rdpcap("samples/beacon_sample.pcap")

    # Convert cipher identifiers into readable names
    cipher_names = {
        4: "CCMP-128"
    }

    akm_names = {
        1: "802.1X",
        2: "PSK"
    }

    # Store information about detected networks
    networks = []

    # Count Beacon frames
    beacon_count = 0

    # Examine every packet
    for packet in packets:

        # Process only Beacon frames
        if not packet.haslayer(Dot11Beacon):
            continue

        # Count every Beacon frame, including duplicates
        beacon_count += 1

        # Extract BSSID
        bssid = packet[Dot11].addr3

        # Extract SSID information element
        ssid = None
        element = packet.getlayer(Dot11Elt)

        while isinstance(element, Dot11Elt):

            if element.ID == 0:
                ssid = element.info.decode(
                    "utf-8",
                    errors="replace"
                )
                break

            element = element.payload

        # Handle missing and hidden SSIDs
        if ssid is None:
            ssid = "<SSID not found>"
        elif ssid == "":
            ssid = "<Hidden SSID>"

        # Extract channel
        channel = "Unknown"

        if packet.haslayer(Dot11EltDSSSet):
            channel = packet[Dot11EltDSSSet].channel

        # Extract security information
        security = "Unknown"

        if packet.haslayer(Dot11EltRSN):

            rsn = packet[Dot11EltRSN]

            if rsn.akm_suites:
                akm_value = rsn.akm_suites[0].suite

                authentication = akm_names.get(
                    akm_value,
                    f"Unknown ({akm_value})"
                )

                if authentication == "PSK":
                    security = "WPA2-PSK"
                else:
                    security = authentication

        # Skip duplicate access points
        if any(existing["bssid"] == bssid for existing in networks):
            continue

        # Store the network details
        network = {
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "security": security
        }

        networks.append(network)

    # Display the final network summary
    print("\n========== WI-FI NETWORK SUMMARY ==========\n")

    print(
        f"{'SSID':<18}"
        f"{'BSSID':<23}"
        f"{'CHANNEL':<10}"
        f"{'SECURITY'}"
    )

    print("-" * 70)

    for network in networks:

        print(
            f"{network['ssid']:<18}"
            f"{network['bssid']:<23}"
            f"{str(network['channel']):<10}"
            f"{network['security']}"
        )

    # Display capture statistics
    print("\n========== CAPTURE STATISTICS ==========")
    print("Total packets captured:", len(packets))
    print("Total Beacon frames:", beacon_count)
    print("Total unique access points:", len(networks))
    # Export the detected networks
    export_to_csv(networks)

if __name__ == "__main__":
    main()
