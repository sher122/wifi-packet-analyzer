
import csv

from scapy.all import rdpcap

try:
    # Import when running as a Python module or during pytest
    from .analyzer import analyze_packets

except ImportError:
    # Import when running directly: python src/read_capture.py
    from analyzer import analyze_packets

def export_to_csv(networks):

    # Define the output CSV file
    output_file = "reports/wifi_networks.csv"

    fieldnames = [
        "SSID",
        "BSSID",
        "Channel",
        "Security"
    ]

    # Write network information into CSV
    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()

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

    # Analyze packets using our new analyzer module
    networks, beacon_count = analyze_packets(packets)

    # Display network summary
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

    # Export network information
    export_to_csv(networks)


if __name__ == "__main__":
    main()
