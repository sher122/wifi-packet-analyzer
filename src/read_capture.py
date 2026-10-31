
import csv
import sys

from scapy.all import rdpcap, Ether, Dot11

try:
    from .analyzer import analyze_packets
except ImportError:
    from analyzer import analyze_packets


def export_to_csv(networks, output_file="reports/wifi_networks.csv"):
    """Export discovered Wi-Fi networks to a CSV file."""

    fieldnames = ["SSID", "BSSID", "Channel", "Security"]

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for network in networks:
            writer.writerow({
                "SSID": network["ssid"],
                "BSSID": network["bssid"],
                "Channel": network["channel"],
                "Security": network["security"]
            })

    print("\nCSV report generated:", output_file)


def main(capture_file="samples/beacon_sample.pcap"):
    """Read a capture and analyze its Wi-Fi Beacon frames."""

    print("\nReading capture:", capture_file)

    packets = rdpcap(capture_file)

    # Identify the packet formats in the capture.
    ethernet_count = sum(packet.haslayer(Ether) for packet in packets)
    wifi_count = sum(packet.haslayer(Dot11) for packet in packets)

    print("Total packets captured:", len(packets))
    print("Ethernet packets:", ethernet_count)
    print("802.11 packets:", wifi_count)

    # Stop if the capture contains Ethernet packets but no 802.11 frames.
    if packets and wifi_count == 0 and ethernet_count > 0:
        print("\nWARNING: This capture contains Ethernet-format packets.")
        print("Raw 802.11 frames are required for Beacon analysis.")
        print("No Wi-Fi network report was generated.")
        return

    if not packets:
        print("\nWARNING: The capture file is empty.")
        return

    # Analyze the captured packets.
    networks, beacon_count = analyze_packets(packets)

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

    print("\n========== CAPTURE STATISTICS ==========")
    print("Total packets captured:", len(packets))
    print("Total Beacon frames:", beacon_count)
    print("Total unique access points:", len(networks))

    export_to_csv(networks)


if __name__ == "__main__":
    # Allow an optional PCAP filename from the command line.
    capture_file = (
        sys.argv[1] if len(sys.argv) > 1
        else "samples/beacon_sample.pcap"
    )

    main(capture_file)
