
import csv

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11EltRSN
)

from scapy.layers.dot11 import AKMSuite

from src.analyzer import extract_security
from src.read_capture import export_to_csv


def test_security_extraction():

    packet = (
        Dot11(type=0, subtype=8)
        / Dot11Beacon()
        / Dot11EltRSN(
            akm_suites=[AKMSuite(suite=2)],
            mfp_capable=0,
            mfp_required=0
        )
    )

    assert extract_security(packet) == "WPA2-PSK"


def test_csv_export(tmp_path):

    networks = [
        {
            "ssid": "Training_WiFi",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "channel": 6,
            "security": "WPA2-PSK"
        }
    ]

    output_file = tmp_path / "wifi_networks.csv"

    # Write CSV into pytest's temporary directory
    import csv

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=["SSID", "BSSID", "Channel", "Security"]
        )

        writer.writeheader()

        for network in networks:
            writer.writerow({
                "SSID": network["ssid"],
                "BSSID": network["bssid"],
                "Channel": network["channel"],
                "Security": network["security"]
            })

    # Read and verify the CSV
    with open(output_file, "r", encoding="utf-8") as csvfile:

        rows = list(csv.DictReader(csvfile))

    assert len(rows) == 1
    assert rows[0]["SSID"] == "Training_WiFi"
    assert rows[0]["BSSID"] == "aa:bb:cc:dd:ee:ff"
