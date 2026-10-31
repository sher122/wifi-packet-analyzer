
from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltDSSSet
)

from src.analyzer import (
    extract_ssid,
    extract_channel,
    analyze_packets
)


def create_beacon(ssid_info, bssid):
    """Create a synthetic Beacon for testing."""

    packet = (
        Dot11(
            type=0,
            subtype=8,
            addr1="FF:FF:FF:FF:FF:FF",
            addr2=bssid,
            addr3=bssid
        )
        / Dot11Beacon()
    )

    # Add SSID element only when requested
    if ssid_info is not None:
        packet = packet / Dot11Elt(
            ID=0,
            info=ssid_info
        )

    return packet


def test_normal_ssid():

    packet = create_beacon(
        b"Training_WiFi",
        "AA:BB:CC:DD:EE:FF"
    )

    assert extract_ssid(packet) == "Training_WiFi"


def test_hidden_ssid():

    packet = create_beacon(
        b"",
        "AA:BB:CC:DD:EE:FF"
    )

    assert extract_ssid(packet) == "<Hidden SSID>"


def test_missing_ssid():

    packet = create_beacon(
        None,
        "AA:BB:CC:DD:EE:FF"
    )

    assert extract_ssid(packet) == "<SSID not found>"


def test_duplicate_access_point():

    beacon_1 = create_beacon(
        b"Training_WiFi",
        "AA:BB:CC:DD:EE:FF"
    )

    beacon_2 = create_beacon(
        b"Training_WiFi",
        "AA:BB:CC:DD:EE:FF"
    )

    networks, beacon_count = analyze_packets(
        [beacon_1, beacon_2]
    )

    assert beacon_count == 2
    assert len(networks) == 1


def test_multiple_access_points():

    beacon_1 = create_beacon(
        b"Training_WiFi",
        "AA:BB:CC:DD:EE:FF"
    )

    beacon_2 = create_beacon(
        b"Office_WiFi",
        "11:22:33:44:55:66"
    )

    beacon_3 = create_beacon(
        b"Guest_WiFi",
        "22:33:44:55:66:77"
    )

    networks, beacon_count = analyze_packets(
        [beacon_1, beacon_2, beacon_3]
    )

    assert beacon_count == 3
    assert len(networks) == 3


def test_non_beacon_packet_is_ignored():

    packet = Dot11(
        type=2,
        subtype=0,
        addr1="FF:FF:FF:FF:FF:FF",
        addr2="AA:BB:CC:DD:EE:FF",
        addr3="11:22:33:44:55:66"
    )

    networks, beacon_count = analyze_packets([packet])

    assert beacon_count == 0
    assert len(networks) == 0


def test_channel_extraction():

    packet = (
        Dot11(type=0, subtype=8)
        / Dot11Beacon()
        / Dot11EltDSSSet(channel=6)
    )

    assert extract_channel(packet) == 6
