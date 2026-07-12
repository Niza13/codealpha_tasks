import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# additional security filter
SECURITY_KEYWORDS = [b"user", b"password", b"pass", b"login", b"secret", b"cookie", b"token"]

def process_packet(packet):
    
    # if packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        # ip_type = ip_layer.type
        
        # protocol name according to IANA assigned number
        protocol_name = "Other"
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"

        # packet.show()

        print(f"\n[+] New Packet: \n")
        print(f"    ├─Src:{src_ip} -> Dst: {dst_ip}")
        print(f"    └─Protocol: {protocol_name}")
        # print(f"    Type: {ip_type}\n")


        # Analyze Layer 4 (Transport) for ports & Payload
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            window = tcp_layer.window
            ip_layer = packet[IP]
            ttl = ip_layer.ttl
            detected_os = guess_os(ttl,window)
            print(f"    └─[Ports] Src: {tcp_layer.sport} -> Dst: {tcp_layer.dport}")
            print(f"    └─TTL: {ttl}\n    └─Window_size: {window}\n    └─OS: {detected_os} \n")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"    ├─[Ports] Src: {udp_layer.sport} -> Dst: {udp_layer.dport}")
            
        elif packet.haslayer(ICMP):
            print(f"    ├─[ICMP] Type: {packet[ICMP].type} | Code: {packet[ICMP].code}")

        # Extract and display raw payload data if it exists
        if packet.haslayer(Raw):
            payload = packet[Raw].load.lower()

            for keyword in SECURITY_KEYWORDS:
                if keyword in payload:
                    print(f"\n[SECURITY ALERT] Potential Sensitive Data Leaked in Cleartext!")
                    print(f"    ├─ Origin IP: {packet[IP].src}")
                    print(f"    └─ Snippet: {packet[Raw].load[:100]}")
            # Attempt to decode payload into readable text, fall back to hex/string representation
            try:
                decoded_payload = payload.decode('utf-8', errors='ignore').strip()
                if decoded_payload:
                    # Clean up long/noisy output for display
                    readable_payload = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in decoded_payload)
                    print(f"    └─[Payload] {readable_payload[:100]}")
            except Exception:
                print(f"    └─[Payload] Raw Bytes: {payload[:50]}")

# function to passively fingerprint the OS based on TTL and TCP Window Size boundaries.
def guess_os(ttl, window_size):
    
    # Windows typically starts with a TTL of 128
    if ttl > 64 and ttl <= 128:
        if window_size in [64240, 65535, 16384]:
            return "Windows (10/11/Server)"
        return "Windows (Likely)"
    
    # Linux/Unix/Mac typically start with a TTL of 64
    elif ttl <= 64:
        if window_size in [5840, 29200]:
            return "Linux (Ubuntu/Debian/Kali)"
        elif window_size == 65535:
            return "macOS / iOS or Android"
        return "Linux/Unix-based"
    
    # Network equipment (Routers/Switches) often use high TTLs like 255
    elif ttl > 128:
        return "Cisco / Network Device"
        
    return "Unknown OS Signature"

def main():
    print("="*60)
    print("            STARTING BASIC PYTHON NETWORK SNIFFER           ")
    print("="*60)
    print("[*] Listening for network traffic... Press Ctrl+C to stop.")
    
    try:
        
        # sniff() is Scapy's capture function
        # prn: callback function to run on each packet
        # store: 0 means we process without keeping it all in memory
        sniff(prn=process_packet, store=0)
    except PermissionError:
        print("\n[!] Error: Root/Administrator privileges required to sniff packets.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] Sniffer stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()