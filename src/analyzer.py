
from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltDSSSet,
    Dot11EltRSN
)


def extract_ssid(packet):
    """Extract the SSID from a Beacon frame."""

    element = packet.getlayer(Dot11Elt)

    while isinstance(element, Dot11Elt):

        if element.ID == 0:
            ssid = element.info.decode(
                "utf-8",
                errors="replace"
            )

            if ssid == "":
                return "<Hidden SSID>"

            return ssid

        element = element.payload

    return "<SSID not found>"


def extract_channel(packet):
    """Extract the advertised 2.4 GHz DS channel."""

    if packet.haslayer(Dot11EltDSSSet):
        return packet[Dot11EltDSSSet].channel

    return "Unknown"


def extract_security(packet):
    """Extract a simplified authentication label."""

    if not packet.haslayer(Dot11EltRSN):
        return "Unknown"

    rsn = packet[Dot11EltRSN]

    if not rsn.akm_suites:
        return "Unknown"

    akm_value = rsn.akm_suites[0].suite

    if akm_value == 2:
        return "WPA2-PSK"

    if akm_value == 1:
        return "802.1X"

    return f"Unknown ({akm_value})"


def analyze_packets(packets):
    """Analyze packets and return unique Beacon networks."""

    networks = []
    beacon_count = 0

    for packet in packets:

        if not packet.haslayer(Dot11Beacon):
            continue

        beacon_count += 1

        bssid = packet[Dot11].addr3

        # Skip duplicate BSSIDs
        if any(
            network["bssid"] == bssid
            for network in networks
        ):
            continue

        network = {
            "ssid": extract_ssid(packet),
            "bssid": bssid,
            "channel": extract_channel(packet),
            "security": extract_security(packet)
        }

        networks.append(network)

    return networks, beacon_count
