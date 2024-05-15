from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP

# List to store packets
packets = []

# Function to process each packet
def packet_callback(packet):
    packets.append(packet)
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")
    if TCP in packet:
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        payload = packet[TCP].payload
        print(f"TCP Packet: {tcp_sport} -> {tcp_dport}, Payload: {payload}")
    if UDP in packet:
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport
        payload = packet[UDP].payload
        print(f"UDP Packet: {udp_sport} -> {udp_dport}, Payload: {payload}")
    if ICMP in packet:
        print("ICMP Packet")

# Sniff packets with a filter for IP packets
sniff(filter="ip", prn=packet_callback, store=0, count=10)  # Capture 10 packets for this example

# Save packets to a file
wrpcap('captured_packets.pcap', packets)
