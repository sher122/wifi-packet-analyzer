# Wi-Fi Packet Analyzer

A Python-based IEEE 802.11 Wi-Fi Beacon frame analyzer built using Scapy.

## Overview

This project analyzes packet capture files (PCAP and PCAPNG) to identify IEEE 802.11 Beacon frames and extract information about Wi-Fi access points.

It extracts:

- SSID (Wi-Fi network name)
- BSSID (access point MAC address)
- Advertised Wi-Fi channel
- Simplified security classification
- Total Beacon frames and unique access points

The analyzer also exports discovered network information to a CSV report.

It includes capture-format detection to distinguish Ethernet traffic from raw IEEE 802.11 frames.

## Features

- IEEE 802.11 Beacon frame construction and analysis
- SSID extraction, including hidden and missing SSIDs
- BSSID identification and duplicate access point detection
- Channel extraction from the DS Parameter Set information element
- Simplified WPA2-Personal security classification using the RSN element
- PCAP and PCAPNG file reading
- Ethernet and 802.11 packet detection
- CSV report generation
- Automated testing using pytest
- Graceful handling of empty and unsupported capture formats

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
├── .gitignore
└── README.md
```

## Requirements

- Python 3.9 or later
- Scapy 2.8.0
- Pytest 8.4.2

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd wifi-packet-analyzer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the Analyzer

Analyze the included sample capture:

```bash
python src/read_capture.py
```

Analyze a specific capture file:

```bash
python src/read_capture.py samples/your_capture.pcapng
```

The analyzer identifies packet formats, processes supported 802.11 Beacon frames, and generates a CSV report.

Default report location:

```text
reports/wifi_networks.csv
```

## Run Automated Tests

Execute the test suite:

```bash
python -m pytest -v
```

The current test suite contains 11 tests covering:

- Normal SSID extraction
- Hidden SSID handling
- Missing SSID handling
- Duplicate access point detection
- Multiple access point analysis
- Non-Beacon packet filtering
- Channel extraction
- Security extraction
- CSV export
- Ethernet capture detection
- Empty capture handling

## Sample Analysis

The included synthetic capture contains four Beacon frames representing three unique access points.

| SSID | BSSID | Channel | Security |
|---|---|---:|---|
| Training_WiFi | aa:bb:cc:dd:ee:ff | 6 | WPA2-PSK |
| Office_WiFi | 11:22:33:44:55:66 | 11 | WPA2-PSK |
| Guest_WiFi | 22:33:44:55:66:77 | 1 | WPA2-PSK |

## Real-World Capture Testing

The analyzer was also tested against a real Wi-Fi traffic capture created using Wireshark on Windows.

The capture contained:

- 12,344 Ethernet-format packets
- 0 raw IEEE 802.11 packets
- 0 Beacon frames

The analyzer correctly identified the Ethernet-only capture and displayed a warning explaining that raw 802.11 frames are required for Beacon analysis.

This behavior is related to the wireless adapter and Windows driver capabilities. The tested Realtek RTL8723DE configuration reported monitor mode as unsupported.

## Technical Concepts Demonstrated

- IEEE 802.11 MAC frame structure
- Beacon frame format
- Frame Control field
- SSID, BSSID and channel information
- IEEE 802.11 Information Elements
- RSN (Robust Security Network) information element
- Scapy packet construction and parsing
- PCAP and PCAPNG file handling
- Python modular programming
- Unit testing with pytest
- Git version control

## Current Limitations

- The included sample capture is synthetically generated.
- Live wireless capture is not implemented.
- Raw 802.11 capture requires a compatible adapter, driver and capture configuration.
- Channel extraction currently uses the legacy DS Parameter Set information element.
- Security classification is simplified and based on the advertised RSN authentication suite.
- The analyzer does not perform complete WPA/WPA2/WPA3 security negotiation analysis.

## Future Improvements

- Live 802.11 packet capture
- Improved WPA, WPA2 and WPA3 classification
- Support for additional 802.11 Information Elements
- Better channel detection for 5 GHz and 6 GHz networks
- Beacon interval and capability analysis
- More comprehensive malformed-packet handling

## Disclaimer

This project is intended for educational purposes and authorized network analysis only. Analyze only wireless traffic that you are permitted to capture.
