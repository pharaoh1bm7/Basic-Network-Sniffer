from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"IP {ip_src} -> {ip_dst} (TCP) {tcp_sport} -> {tcp_dport}")
        
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"IP {ip_src} -> {ip_dst} (UDP) {udp_sport} -> {udp_dport}")
        else:
            print(f"IP {ip_src} -> {ip_dst} (Other Protocol)")

print("Starting network sniffer...")
sniff(prn=packet_callback, store=0)
