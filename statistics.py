"""
Statistics Module
Generates statistical analysis and visualizations of network traffic
Uses pandas and matplotlib for data processing and visualization
"""

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend to avoid threading warnings
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from collections import Counter
from datetime import datetime
from typing import Dict, List
import os


class StatisticsGenerator:
    """Generates statistics and visualizations from network analysis"""
    
    def __init__(self, analysis_results: Dict):
        """
        Initialize with analysis results
        
        Args:
            analysis_results: Results from ProtocolAnalyzer
        """
        self.results = analysis_results
        self.charts = []
    
    def generate_all_stats(self, output_dir: str = "reports") -> Dict:
        """
        Generate all statistics and visualizations
        
        Args:
            output_dir: Directory to save charts
        
        Returns:
            Dictionary of generated statistics
        """
        os.makedirs(output_dir, exist_ok=True)
        
        stats = {
            'protocol_summary': self.get_protocol_summary(),
            'ip_summary': self.get_ip_summary(),
            'dns_summary': self.get_dns_summary(),
            'http_summary': self.get_http_summary(),
            'tcp_summary': self.get_tcp_summary(),
            'anomaly_summary': self.get_anomaly_summary()
        }
        
        # Generate visualizations
        self.create_protocol_chart(os.path.join(output_dir, "protocol_distribution.png"))
        self.create_top_ips_chart(os.path.join(output_dir, "top_ips.png"))
        self.create_port_chart(os.path.join(output_dir, "top_ports.png"))
        
        return stats
    
    def get_protocol_summary(self) -> Dict:
        """Get protocol distribution summary"""
        if 'protocol_distribution' in self.results:
            return self.results['protocol_distribution']
        return {}
    
    def get_ip_summary(self) -> Dict:
        """Get IP communication summary"""
        if 'ip_communications' in self.results:
            return {
                'unique_sources': self.results['ip_communications'].get('unique_source_ips', 0),
                'unique_destinations': self.results['ip_communications'].get('unique_destination_ips', 0),
                'top_source_ips': self.results['ip_communications'].get('top_source_ips', {}),
                'top_destination_ips': self.results['ip_communications'].get('top_destination_ips', {})
            }
        return {}
    
    def get_dns_summary(self) -> Dict:
        """Get DNS activity summary"""
        if 'dns_activity' in self.results:
            return {
                'total_queries': self.results['dns_activity'].get('total_queries', 0),
                'total_responses': self.results['dns_activity'].get('total_responses', 0),
                'top_domains': self.results['dns_activity'].get('top_queried_domains', {})
            }
        return {}
    
    def get_http_summary(self) -> Dict:
        """Get HTTP activity summary"""
        if 'http_activity' in self.results:
            return {
                'total_requests': self.results['http_activity'].get('total_requests', 0),
                'methods': self.results['http_activity'].get('methods', {}),
                'top_hosts': self.results['http_activity'].get('top_hosts', {})
            }
        return {}
    
    def get_tcp_summary(self) -> Dict:
        """Get TCP connection summary"""
        if 'tcp_connections' in self.results:
            return {
                'total_connections': self.results['tcp_connections'].get('total_connections', 0),
                'top_ports': self.results['tcp_connections'].get('top_destination_ports', {})
            }
        return {}
    
    def get_anomaly_summary(self) -> Dict:
        """Get anomaly detection summary"""
        if 'suspicious_activity' in self.results:
            return self.results['suspicious_activity']
        return {}
    
    def create_protocol_chart(self, output_file: str):
        """Create protocol distribution pie chart"""
        protocols = self.results.get('protocol_distribution', {})
        
        if not protocols:
            return
        
        labels = []
        sizes = []
        
        for proto, data in protocols.items():
            labels.append(proto)
            sizes.append(data['count'])
        
        plt.figure(figsize=(10, 7))
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#ff99cc', '#c2c2f0']
        
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
        plt.title('Protocol Distribution', fontsize=16, fontweight='bold')
        plt.axis('equal')
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.charts.append(output_file)
        print(f"[+] Protocol chart saved: {output_file}")
    
    def create_top_ips_chart(self, output_file: str):
        """Create top IPs bar chart"""
        ip_data = self.results.get('ip_communications', {})
        
        if not ip_data:
            return
        
        top_src = ip_data.get('top_source_ips', {})
        top_dst = ip_data.get('top_destination_ips', {})
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        # Top source IPs
        if top_src:
            ips = list(top_src.keys())[:10]
            counts = list(top_src.values())[:10]
            
            ax1.barh(range(len(ips)), counts, color='#3498db')
            ax1.set_yticks(range(len(ips)))
            ax1.set_yticklabels(ips)
            ax1.set_xlabel('Packet Count', fontweight='bold')
            ax1.set_title('Top 10 Source IP Addresses', fontsize=14, fontweight='bold')
            ax1.invert_yaxis()
        
        # Top destination IPs
        if top_dst:
            ips = list(top_dst.keys())[:10]
            counts = list(top_dst.values())[:10]
            
            ax2.barh(range(len(ips)), counts, color='#e74c3c')
            ax2.set_yticks(range(len(ips)))
            ax2.set_yticklabels(ips)
            ax2.set_xlabel('Packet Count', fontweight='bold')
            ax2.set_title('Top 10 Destination IP Addresses', fontsize=14, fontweight='bold')
            ax2.invert_yaxis()
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.charts.append(output_file)
        print(f"[+] IP chart saved: {output_file}")
    
    def create_port_chart(self, output_file: str):
        """Create top ports bar chart"""
        tcp_data = self.results.get('tcp_connections', {})
        
        if not tcp_data:
            return
        
        top_ports = tcp_data.get('top_destination_ports', {})
        
        if not top_ports:
            return
        
        ports = list(top_ports.keys())[:15]
        counts = list(top_ports.values())[:15]
        
        # Map common ports to services
        port_services = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP',
            53: 'DNS', 110: 'POP3', 143: 'IMAP', 3306: 'MySQL', 3389: 'RDP',
            8080: 'HTTP-Alt', 23: 'Telnet', 20: 'FTP-Data'
        }
        
        labels = [f"{port}\n({port_services.get(port, 'Unknown')})" for port in ports]
        
        plt.figure(figsize=(14, 7))
        bars = plt.bar(range(len(ports)), counts, color='#2ecc71')
        plt.xticks(range(len(ports)), labels, rotation=45, ha='right')
        plt.xlabel('Port (Service)', fontsize=12, fontweight='bold')
        plt.ylabel('Connection Count', fontsize=12, fontweight='bold')
        plt.title('Top 15 TCP Destination Ports', fontsize=16, fontweight='bold')
        plt.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.charts.append(output_file)
        print(f"[+] Port chart saved: {output_file}")
    
    def get_generated_charts(self) -> List[str]:
        """Get list of generated chart files"""
        return self.charts
    
    def create_timeline_data(self, packets: List) -> pd.DataFrame:
        """
        Create timeline DataFrame from packets
        
        Args:
            packets: List of Scapy packets
        
        Returns:
            pandas DataFrame with timeline data
        """
        timeline_data = []
        
        for packet in packets:
            if hasattr(packet, 'time'):
                timestamp = datetime.fromtimestamp(float(packet.time))
                timeline_data.append({
                    'timestamp': timestamp,
                    'protocol': packet.sprintf("%IP.proto%") if packet.haslayer('IP') else 'Other'
                })
        
        if timeline_data:
            df = pd.DataFrame(timeline_data)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            return df
        
        return pd.DataFrame()


if __name__ == "__main__":
    print("Statistics Generator Module - Testing")
    print("=" * 70)
