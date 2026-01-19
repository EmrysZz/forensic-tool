"""
Sample PCAP Generator
Creates a sample PCAP file for testing the Network Traffic Analyzer
"""

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap, Raw
import random

def generate_sample_pcap(output_file="sample.pcap", packet_count=100):
    """
    Generate a sample PCAP file with various protocols
    
    Args:
        output_file: Path to output PCAP file
        packet_count: Number of packets to generate
    """
    
    packets = []
    
    # Sample IPs
    internal_ips = ["192.168.1.{}".format(i) for i in range(10, 20)]
    external_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "208.80.154.224"]
    suspicious_ip = "203.0.113.45"  # For port scan simulation
    
    print(f'[*] Generating {packet_count} sample packets...')
    
    for i in range(packet_count):
        src_ip = random.choice(internal_ips)
        
        # Normal traffic (70%)
        if i < packet_count * 0.7:
            dst_ip = random.choice(external_ips)
            protocol = random.choice(['tcp', 'udp', 'dns'])
            
            if protocol == 'tcp':
                # TCP traffic (HTTP, HTTPS, etc.)
                dst_port = random.choice([80, 443, 8080, 22, 21])
                pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port)
                
                # Add some HTTP-like payload
                if dst_port == 80:
                    http_request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
                    pkt = pkt / Raw(load=http_request)
            
            elif protocol == 'udp':
                # UDP traffic
                dst_port = random.choice([53, 123, 161])
                pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=dst_port)
            
            else:  # DNS
                # DNS query
                dst_ip = "8.8.8.8"
                domain = random.choice([
                    "www.example.com", 
                    "api.service.com", 
                    "mail.company.org",
                    "cdn.website.net"
                ])
                pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        
        # Port scan simulation (20%)
        elif i < packet_count * 0.9:
            # Simulate port scanning from suspicious IP
            dst_ip = random.choice(internal_ips)
            dst_port = random.randint(1, 1000)
            pkt = IP(src=suspicious_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='S')
        
        # SYN flood simulation (10%)
        else:
            # SYN flood attack
            dst_ip = random.choice(internal_ips)
            dst_port = 80
            pkt = IP(src=suspicious_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='S')
        
        packets.append(pkt)
    
    # Write to PCAP file
    wrpcap(output_file, packets)
    print(f'[+] Sample PCAP file created: {output_file}')
    print(f'[+] Total packets: {len(packets)}')
    print(f'[+] Includes:')
    print(f'    - Normal TCP/UDP/DNS traffic')
    print(f'    - Port scanning activity (simulated)')
    print(f'    - SYN flood attack (simulated)')
    print(f'\n[!] This is a SIMULATED file for testing purposes only!')


if __name__ == "__main__":
    import sys
    
    output_file = sys.argv[1] if len(sys.argv) > 1 else "examples/sample.pcap"
    packet_count = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    
    generate_sample_pcap(output_file, packet_count)
