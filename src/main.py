# Import the IEEE 802.11 packet layer
from scapy.all import Dot11


def main():

    # Create an IEEE 802.11 frame
    wifi_frame = Dot11()

    # Display a short summary
    print("Our first Wi-Fi frame:")
    print(wifi_frame.summary())

    # Display detailed frame information
    print("\nDetailed Wi-Fi frame:")
    wifi_frame.show()


if __name__ == "__main__":
    main()