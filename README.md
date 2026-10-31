# Wi-Fi Packet Analyzer

A Python-based 802.11 Wi-Fi Beacon frame analyzer built using Scapy.

## Overview

This project reads packet captures (PCAP files), identifies IEEE 802.11 Beacon frames, and extracts information about nearby Wi-Fi networks.

It currently analyzes:
- SSID (network name)
- BSSID (access point MAC address)
- Advertised Wi-Fi channel
- Simplified security classification
- Total Beacon frames and unique access points

The analyzer also exports discovered network information to a CSV report.

## Project Structure

```text
wifi-packet-analyzer/
├── src/
│   ├── main.py
│   ├── read_capture.py
│   └── analyzer.py
├── tests/
│   ├── test_analyzer.py
│   └── test_reports.py
├── samples/
│   └── beacon_sample.pcap
├── reports/
│   └── wifi_networks.csv
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.9
- Scapy 2.8.0
- Pytest 8.4.2

## Installation

Clone the repository and install dependencies:

```bash
pip install -r requirements.txt
```

## Run the Analyzer

From the project root:

```bash
python src/read_capture.py
```

The analyzer reads the sample PCAP file and generates:

```text
reports/wifi_networks.csv
```

## Run Tests

```bash
python -m pytest -v
```

## Sample Output

The sample capture contains four Beacon frames representing three unique access points.

| SSID | Channel | Security |
|---|---:|---|
| Training_WiFi | 6 | WPA2-PSK |
| Office_WiFi | 11 | WPA2-PSK |
| Guest_WiFi | 1 | WPA2-PSK |

## Technical Concepts Demonstrated

- IEEE 802.11 Beacon frame structure
- Scapy packet parsing and construction
- SSID and BSSID extraction
- Information Element parsing
- RSN information element and security classification
- PCAP file handling
- CSV report generation
- Python unit testing with pytest
- Git version control

## Current Limitations

- The included PCAP is synthetically generated for learning and testing.
- Channel extraction currently uses the legacy DS Parameter Set information element.
- Security classification is simplified and based on the RSN authentication suite.
- Live wireless capture is not implemented yet.

## Future Improvements

- Support live Wi-Fi packet capture.
- Improve WPA/WPA2/WPA3 security classification.
- Add support for more 802.11 information elements.
- Expand channel detection for 5 GHz and 6 GHz networks.

## Disclaimer

This project is intended for educational and authorized network analysis. Only analyze wireless traffic that you are permitted to capture.
