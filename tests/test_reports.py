
import csv

from scapy.all import (
    Ether,
    IP,
    Dot11,
    Dot11Beacon,
    Dot11EltRSN
)

from scapy.layers.dot11 import AKMSuite

import src.read_capture as read_capture
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

    # Test our actual CSV export function.
    export_to_csv(networks, str(output_file))

    with open(output_file, "r", encoding="utf-8") as csvfile:
        rows = list(csv.DictReader(csvfile))

    assert len(rows) == 1
    assert rows[0]["SSID"] == "Training_WiFi"
    assert rows[0]["BSSID"] == "aa:bb:cc:dd:ee:ff"
    assert rows[0]["Channel"] == "6"
    assert rows[0]["Security"] == "WPA2-PSK"


def test_ethernet_capture_warning(monkeypatch, capsys):

    # Simulate an Ethernet packet.
    packets = [Ether() / IP()]

    # Replace file reading with our test packet.
    monkeypatch.setattr(
        read_capture,
        "rdpcap",
        lambda filename: packets
    )

    read_capture.main("fake_capture.pcap")

    output = capsys.readouterr().out

    assert "Ethernet-format packets" in output
    assert "Raw 802.11 frames are required" in output
    assert "No Wi-Fi network report was generated" in output


def test_empty_capture_warning(monkeypatch, capsys):

    # Simulate an empty capture file.
    monkeypatch.setattr(
        read_capture,
        "rdpcap",
        lambda filename: []
    )

    read_capture.main("empty_capture.pcap")

    output = capsys.readouterr().out

    assert "the capture file is empty" in output.lower()