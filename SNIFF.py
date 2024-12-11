from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    """Process and display information from a captured packet."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "Unknown"
        payload = "No payload"

        if TCP in packet:
            protocol = "TCP"
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
        elif UDP in packet:
            protocol = "UDP"
            payload = bytes(packet[UDP].payload).decode('utf-8', errors='ignore')

        print(f"\nPacket captured:")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload if payload else 'No payload'}")

if __name__ == "__main__":
    print("Starting packet sniffer...")
    print("Press Ctrl+C to stop.")

    # Capture packets (ensure to run this script with administrative privileges)
    try:
        sniff(prn=process_packet, filter="ip", store=0)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped.")
    except PermissionError:
        print("Permission denied. Please run this script as an administrator/root user.")
