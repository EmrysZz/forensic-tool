"""
Protocol Analyzer Module
Analyzes network protocols and extracts forensic information
Uses Scapy for deep packet inspection
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from collections import defaultdict, Counter
from typing import Dict, List, Tuple
from datetime import datetime


class ProtocolAnalyzer:
    """Analyzes network protocols from captured packets"""
    
    def __init__(self, packets: List):
        """
        Initialize analyzer with packet list
        
        Args:
            packets: List of Scapy packets
        """
        self.packets = packets
        self.protocol_stats = defaultdict(int)
        self.ip_conversations = defaultdict(int)
        self.dns_queries = []
        self.http_requests = []
        self.suspicious_ips = set()
        self.port_scans = []
    
    def analyze_all(self) -> Dict:
        """
        Perform comprehensive analysis on all packets
        
        Returns:
            Dictionary containing analysis results
        """
        print("[*] Starting protocol analysis...")
        
        results = {
            'total_packets': len(self.packets),  # Add total packet count
            'protocol_distribution': self.analyze_protocols(),
            'ip_communications': self.analyze_ip_traffic(),
            'dns_activity': self.analyze_dns(),
            'http_activity': self.analyze_http(),
            'tcp_connections': self.analyze_tcp(),
            'udp_connections': self.analyze_udp(),
            'suspicious_activity': self.detect_anomalies()
        }
        
        print("[+] Analysis complete")
        return results
    
    def analyze_protocols(self) -> Dict:
        """
        Analyze protocol distribution
        
        Returns:
            Protocol statistics
        """
        protocol_count = Counter()
        
        for packet in self.packets:
            if IP in packet:
                proto = packet[IP].proto
                if proto == 6:
                    protocol_count['TCP'] += 1
                elif proto == 17:
                    protocol_count['UDP'] += 1
                elif proto == 1:
                    protocol_count['ICMP'] += 1
                else:
                    protocol_count[f'Other ({proto})'] += 1
            
            if ARP in packet:
                protocol_count['ARP'] += 1
            
            if DNS in packet:
                protocol_count['DNS'] += 1
        
        total = sum(protocol_count.values())
        protocol_percentages = {
            proto: {
                'count': count,
                'percentage': (count / total * 100) if total > 0 else 0
            }
            for proto, count in protocol_count.items()
        }
        
        return protocol_percentages
    
    def analyze_ip_traffic(self) -> Dict:
        """
        Analyze IP traffic patterns
        
        Returns:
            IP communication statistics
        """
        src_ips = Counter()
        dst_ips = Counter()
        conversations = Counter()
        
        for packet in self.packets:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                
                src_ips[src] += 1
                dst_ips[dst] += 1
                
                # Track conversations (bidirectional)
                conv = tuple(sorted([src, dst]))
                conversations[conv] += 1
        
        return {
            'top_source_ips': dict(src_ips.most_common(10)),
            'top_destination_ips': dict(dst_ips.most_common(10)),
            'top_conversations': [
                {'ips': list(conv), 'packet_count': count}
                for conv, count in conversations.most_common(10)
            ],
            'unique_source_ips': len(src_ips),
            'unique_destination_ips': len(dst_ips)
        }
    
    def analyze_dns(self) -> Dict:
        """
        Analyze DNS queries and responses
        
        Returns:
            DNS activity information
        """
        dns_queries = []
        dns_responses = []
        queried_domains = Counter()
        
        for packet in self.packets:
            if DNS in packet:
                if packet[DNS].qr == 0:  # Query
                    if packet[DNS].qd:
                        domain = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                        queried_domains[domain] += 1
                        
                        query_info = {
                            'domain': domain,
                            'type': packet[DNS].qd.qtype,
                            'timestamp': float(packet.time) if hasattr(packet, 'time') else 0
                        }
                        
                        if IP in packet:
                            query_info['source_ip'] = packet[IP].src
                        
                        dns_queries.append(query_info)
                
                elif packet[DNS].qr == 1:  # Response
                    response_info = {
                        'answers': str(packet[DNS].an.rdata) if packet[DNS].an and hasattr(packet[DNS].an, 'rdata') else None,
                        'count': packet[DNS].ancount
                    }
                    dns_responses.append(response_info)
        
        return {
            'total_queries': len(dns_queries),
            'total_responses': len(dns_responses),
            'top_queried_domains': dict(queried_domains.most_common(10)),
            'recent_queries': dns_queries[-20:] if len(dns_queries) > 20 else dns_queries
        }
    
    def analyze_http(self) -> Dict:
        """
        Analyze HTTP traffic
        
        Returns:
            HTTP activity information
        """
        http_requests = []
        http_methods = Counter()
        hosts = Counter()
        
        for packet in self.packets:
            # Check for HTTP in raw payload
            if Raw in packet and TCP in packet:
                payload = packet[Raw].load
                
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    
                    # Check for HTTP request
                    if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                        lines = payload_str.split('\r\n')
                        request_line = lines[0]
                        method = request_line.split()[0]
                        
                        http_methods[method] += 1
                        
                        # Extract host
                        host = None
                        for line in lines[1:]:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                hosts[host] += 1
                                break
                        
                        request_info = {
                            'method': method,
                            'host': host,
                            'request_line': request_line[:100],
                            'timestamp': float(packet.time) if hasattr(packet, 'time') else 0
                        }
                        
                        if IP in packet:
                            request_info.update({
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst
                            })
                        
                        http_requests.append(request_info)
                
                except:
                    pass
        
        return {
            'total_requests': len(http_requests),
            'methods': dict(http_methods),
            'top_hosts': dict(hosts.most_common(10)),
            'recent_requests': http_requests[-20:] if len(http_requests) > 20 else http_requests
        }
    
    def analyze_tcp(self) -> Dict:
        """
        Analyze TCP connections
        
        Returns:
            TCP connection information
        """
        connections = defaultdict(lambda: {'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'packets': 0})
        dst_ports = Counter()
        src_ports = Counter()
        
        for packet in self.packets:
            if TCP in packet and IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                connection_key = (src_ip, src_port, dst_ip, dst_port)
                connections[connection_key]['packets'] += 1
                
                dst_ports[dst_port] += 1
                src_ports[src_port] += 1
                
                # Track TCP flags
                if packet[TCP].flags.S:
                    connections[connection_key]['syn'] += 1
                if packet[TCP].flags.A:
                    connections[connection_key]['ack'] += 1
                if packet[TCP].flags.F:
                    connections[connection_key]['fin'] += 1
                if packet[TCP].flags.R:
                    connections[connection_key]['rst'] += 1
        
        return {
            'total_connections': len(connections),
            'top_destination_ports': dict(dst_ports.most_common(10)),
            'top_source_ports': dict(src_ports.most_common(10)),
            'connection_sample': [
                {
                    'source': f"{conn[0]}:{conn[1]}",
                    'destination': f"{conn[2]}:{conn[3]}",
                    'packets': info['packets'],
                    'flags': {k: v for k, v in info.items() if k != 'packets'}
                }
                for conn, info in list(connections.items())[:10]
            ]
        }
    
    def analyze_udp(self) -> Dict:
        """
        Analyze UDP traffic
        
        Returns:
            UDP connection information
        """
        udp_flows = defaultdict(int)
        dst_ports = Counter()
        src_ports = Counter()
        
        for packet in self.packets:
            if UDP in packet and IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                flow_key = (src_ip, src_port, dst_ip, dst_port)
                udp_flows[flow_key] += 1
                
                dst_ports[dst_port] += 1
                src_ports[src_port] += 1
        
        return {
            'total_flows': len(udp_flows),
            'total_packets': sum(udp_flows.values()),
            'top_destination_ports': dict(dst_ports.most_common(10)),
            'top_source_ports': dict(src_ports.most_common(10))
        }
    
    def detect_anomalies(self) -> Dict:
        """
        Detect suspicious patterns in network traffic including DDoS attacks and malicious file transfers
        
        Returns:
            Anomaly detection results
        """
        anomalies = {
            'port_scans': self.detect_port_scans(),
            'syn_floods': self.detect_syn_floods(),
            'udp_floods': self.detect_udp_floods(),
            'icmp_floods': self.detect_icmp_floods(),
            'high_volume_ips': self.detect_high_volume_ips(),
            'ddos_indicators': self.detect_ddos_patterns(),
            'malicious_transfers': self.detect_malicious_file_transfers()
        }
        
        return anomalies
    
    def detect_port_scans(self) -> List[Dict]:
        """Detect potential port scanning activity"""
        ip_ports = defaultdict(set)
        
        for packet in self.packets:
            if TCP in packet and IP in packet:
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                ip_ports[src_ip].add(dst_port)
        
        # Flag IPs scanning more than 5 different ports (lowered threshold for better detection)
        suspicious = []
        for ip, ports in ip_ports.items():
            if len(ports) > 5:
                suspicious.append({
                    'source_ip': ip,
                    'ports_scanned': len(ports),
                    'severity': 'CRITICAL' if len(ports) > 50 else ('HIGH' if len(ports) > 20 else 'MEDIUM'),
                    'attack_type': 'Port Scan'
                })
        
        return suspicious
    
    def detect_syn_floods(self) -> List[Dict]:
        """Detect potential SYN flood attacks (DDoS indicator)"""
        syn_counts = Counter()
        syn_ack_counts = Counter()
        
        for packet in self.packets:
            if TCP in packet and IP in packet:
                src_ip = packet[IP].src
                # Count SYN packets
                if packet[TCP].flags.S and not packet[TCP].flags.A:
                    syn_counts[src_ip] += 1
                # Count SYN-ACK responses
                elif packet[TCP].flags.S and packet[TCP].flags.A:
                    syn_ack_counts[src_ip] += 1
        
        # Flag IPs with excessive SYN packets (lowered threshold: 25+)
        suspicious = []
        for ip, count in syn_counts.items():
            if count > 25:  # Lowered from 50 for better detection
                # Check SYN/SYN-ACK ratio for incomplete handshakes
                syn_ack = syn_ack_counts.get(ip, 0)
                ratio = count / (syn_ack + 1)  # Avoid division by zero
                
                severity = 'CRITICAL' if count > 500 else ('HIGH' if count > 100 else 'MEDIUM')
                
                suspicious.append({
                    'source_ip': ip,
                    'syn_count': count,
                    'syn_ack_count': syn_ack,
                    'incomplete_handshake_ratio': round(ratio, 2),
                    'severity': severity,
                    'attack_type': 'SYN Flood (DDoS)'
                })
        
        return suspicious
    
    def detect_udp_floods(self) -> List[Dict]:
        """Detect potential UDP flood attacks (DDoS indicator)"""
        udp_counts = Counter()
        
        for packet in self.packets:
            if UDP in packet and IP in packet:
                src_ip = packet[IP].src
                udp_counts[src_ip] += 1
        
        # Flag IPs with excessive UDP packets (lowered threshold: 50+)
        suspicious = []
        for ip, count in udp_counts.items():
            if count > 50:  # Lowered from 100
                severity = 'CRITICAL' if count > 500 else ('HIGH' if count > 150 else 'MEDIUM')
                
                suspicious.append({
                    'source_ip': ip,
                    'udp_packet_count': count,
                    'severity': severity,
                    'attack_type': 'UDP Flood (DDoS)'
                })
        
        return suspicious
    
    def detect_icmp_floods(self) -> List[Dict]:
        """Detect potential ICMP flood attacks (DDoS indicator)"""
        icmp_counts = Counter()
        
        for packet in self.packets:
            if ICMP in packet and IP in packet:
                src_ip = packet[IP].src
                icmp_counts[src_ip] += 1
        
        # Flag IPs with excessive ICMP packets (lowered threshold: 25+)
        suspicious = []
        for ip, count in icmp_counts.items():
            if count > 25:  # Lowered from 50
                severity = 'CRITICAL' if count > 250 else ('HIGH' if count > 75 else 'MEDIUM')
                
                suspicious.append({
                    'source_ip': ip,
                    'icmp_packet_count': count,
                    'severity': severity,
                    'attack_type': 'ICMP Flood / Ping Flood (DDoS)'
                })
        
        return suspicious
    
    def detect_ddos_patterns(self) -> List[Dict]:
        """Detect overall DDoS attack patterns"""
        total_packets = len(self.packets)
        patterns = []
        
        # Calculate packet rate if timestamps available
        if self.packets and hasattr(self.packets[0], 'time'):
            first_time = float(self.packets[0].time)
            last_time = float(self.packets[-1].time)
            duration = last_time - first_time
            
            if duration > 0:
                packets_per_second = total_packets / duration
                
                # Flag high packet rates (volumetric attack) - lowered threshold
                if packets_per_second > 500:  # Lowered from 1000
                    patterns.append({
                        'pattern': 'High Packet Rate',
                        'packets_per_second': round(packets_per_second, 2),
                        'total_packets': total_packets,
                        'duration_seconds': round(duration, 2),
                        'severity': 'CRITICAL' if packets_per_second > 5000 else ('HIGH' if packets_per_second > 1000 else 'MEDIUM'),
                        'indication': 'Volumetric DDoS Attack'
                    })
        
        # Check for multiple source IPs targeting single destination (distributed attack)
        dst_attack_counts = Counter()
        src_by_dst = defaultdict(set)
        
        for packet in self.packets:
            if IP in packet:
                dst_ip = packet[IP].dst
                src_ip = packet[IP].src
                dst_attack_counts[dst_ip] += 1
                src_by_dst[dst_ip].add(src_ip)
        
        for dst_ip, count in dst_attack_counts.items():
            unique_sources = len(src_by_dst[dst_ip])
            if unique_sources > 5 and count > 200:  # Lowered thresholds: 5+ sources, 200+ packets
                patterns.append({
                    'pattern': 'Distributed Attack',
                    'target_ip': dst_ip,
                    'unique_attackers': unique_sources,
                    'total_packets': count,
                    'severity': 'CRITICAL' if unique_sources > 25 else ('HIGH' if unique_sources > 10 else 'MEDIUM'),
                    'indication': 'DDoS Attack (Multiple Sources)'
                })
        
        return patterns
    
    def detect_high_volume_ips(self) -> List[Dict]:
        """Detect IPs with unusually high traffic volume"""
        ip_packet_counts = Counter()
        
        for packet in self.packets:
            if IP in packet:
                ip_packet_counts[packet[IP].src] += 1
        
        total_packets = len(self.packets)
        suspicious = []
        
        for ip, count in ip_packet_counts.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            if percentage > 3:  # Lowered from 5% for even better detection
                suspicious.append({
                    'ip_address': ip,
                    'packet_count': count,
                    'percentage': round(percentage, 2),
                    'severity': 'CRITICAL' if percentage > 40 else ('HIGH' if percentage > 20 else 'MEDIUM'),
                    'indication': 'High Traffic Volume'
                })
        
        return suspicious
    
    def detect_malicious_file_transfers(self) -> List[Dict]:
        """Detect potential malicious file transfers and data exfiltration"""
        suspicious_transfers = []
        
        # Track large data transfers
        data_volumes = defaultdict(int)
        tcp_large_transfers = defaultdict(int)
        ftp_activity = []
        smb_activity = []
        suspicious_extensions = []
        http_downloads = []
        
        for packet in self.packets:
            if IP in packet:
                src_ip = packet[IP].src
                
                # Track total data volume per IP
                if hasattr(packet, 'len'):
                    data_volumes[src_ip] += packet.len
                
                # Detect FTP activity (ports 20, 21)
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    
                    # FTP
                    if src_port in [20, 21] or dst_port in [20, 21]:
                        ftp_activity.append({
                            'source_ip': src_ip,
                            'destination_ip': packet[IP].dst,
                            'port': dst_port if dst_port in [20, 21] else src_port
                        })
                    
                    # SMB/CIFS (ports 139, 445)
                    if src_port in [139, 445] or dst_port in [139, 445]:
                        smb_activity.append({
                            'source_ip': src_ip,
                            'destination_ip': packet[IP].dst,
                            'port': dst_port if dst_port in [139, 445] else src_port
                        })
                    
                    # Track large TCP transfers (potential file downloads)
                    if hasattr(packet, 'len') and packet.len > 1000:  # Packets > 1KB
                        key = (src_ip, packet[IP].dst, dst_port)
                        tcp_large_transfers[key] += packet.len
                
                # Check for suspicious file extensions and HTTP downloads
                if Raw in packet and TCP in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        
                        # Check for HTTP responses with attachments/downloads
                        if 'HTTP' in payload and 'Content-Type:' in payload:
                            if any(x in payload for x in ['application/', 'attachment', 'octet-stream']):
                                http_downloads.append({
                                    'source_ip': src_ip,
                                    'destination_ip': packet[IP].dst,
                                    'type': 'HTTP Download'
                                })
                        
                        # Check for suspicious file extensions
                        suspicious_exts = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.zip', 
                                         '.rar', '.7z', '.sql', '.db', '.key', '.pem', 
                                         '.docm', '.xlsm', '.jar', '.apk']
                        
                        for ext in suspicious_exts:
                            if ext in payload.lower():
                                suspicious_extensions.append({
                                    'source_ip': src_ip,
                                    'destination_ip': packet[IP].dst,
                                    'file_extension': ext,
                                    'severity': 'HIGH' if ext in ['.exe', '.bat', '.ps1', '.key', '.pem', '.dll'] else 'MEDIUM'
                                })
                                break
                    except:
                        pass
        
        # Flag IPs with large data volumes (lowered threshold: 50KB+)
        total_data = sum(data_volumes.values())
        for ip, volume in data_volumes.items():
            if total_data > 0:
                percentage = (volume / total_data * 100)
                if volume > 50000 and percentage > 5:  # Lowered from 100KB and 10%
                    suspicious_transfers.append({
                        'type': 'Large Data Transfer',
                        'source_ip': ip,
                        'data_volume_bytes': volume,
                        'percentage_of_total': round(percentage, 2),
                        'severity': 'CRITICAL' if volume > 5000000 else ('HIGH' if volume > 500000 else 'MEDIUM'),
                        'indication': 'Potential Data Exfiltration'
                    })
        
        # Flag large TCP transfers (potential file downloads)
        for (src, dst, port), volume in tcp_large_transfers.items():
            if volume > 100000:  # More than 100KB in one flow
                suspicious_transfers.append({
                    'type': 'Large TCP Transfer',
                    'source_ip': src,
                    'destination_ip': dst,
                    'port': port,
                    'data_volume_bytes': volume,
                    'severity': 'HIGH' if volume > 1000000 else 'MEDIUM',
                    'indication': 'Large File Transfer Detected'
                })
        
        # Flag FTP activity
        if ftp_activity:
            unique_ftp = {}
            for activity in ftp_activity:
                key = (activity['source_ip'], activity['destination_ip'])
                if key not in unique_ftp:
                    unique_ftp[key] = activity
            
            for activity in unique_ftp.values():
                suspicious_transfers.append({
                    'type': 'FTP Activity',
                    'source_ip': activity['source_ip'],
                    'destination_ip': activity['destination_ip'],
                    'port': activity['port'],
                    'severity': 'MEDIUM',
                    'indication': 'File Transfer Protocol Activity'
                })
        
        # Flag SMB activity
        if smb_activity:
            unique_smb = {}
            for activity in smb_activity:
                key = (activity['source_ip'], activity['destination_ip'])
                if key not in unique_smb:
                    unique_smb[key] = activity
            
            for activity in unique_smb.values():
                suspicious_transfers.append({
                    'type': 'SMB/CIFS Activity',
                    'source_ip': activity['source_ip'],
                    'destination_ip': activity['destination_ip'],
                    'port': activity['port'],
                    'severity': 'MEDIUM',
                    'indication': 'Network File Sharing Activity'
                })
        
        # Flag HTTP downloads
        if http_downloads:
            unique_http = {}
            for download in http_downloads:
                key = (download['source_ip'], download['destination_ip'])
                if key not in unique_http:
                    unique_http[key] = download
            
            for download in unique_http.values():
                suspicious_transfers.append({
                    'type': 'HTTP File Download',
                    'source_ip': download['source_ip'],
                    'destination_ip': download['destination_ip'],
                    'severity': 'MEDIUM',
                    'indication': 'HTTP File Download Detected'
                })
        
        # Flag suspicious file extensions
        if suspicious_extensions:
            # Get unique transfers
            seen = set()
            for ext_info in suspicious_extensions:
                key = (ext_info['source_ip'], ext_info['file_extension'])
                if key not in seen:
                    seen.add(key)
                    suspicious_transfers.append({
                        'type': 'Suspicious File Extension',
                        'source_ip': ext_info['source_ip'],
                        'destination_ip': ext_info['destination_ip'],
                        'file_extension': ext_info['file_extension'],
                        'severity': ext_info['severity'],
                        'indication': 'Potentially Malicious File Transfer'
                    })
        
        return suspicious_transfers


if __name__ == "__main__":
    print("Protocol Analyzer Module - Testing")
    print("=" * 70)
