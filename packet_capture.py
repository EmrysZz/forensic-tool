"""
Packet Capture Module
Handles loading and basic processing of PCAP files
Uses Scapy for packet manipulation
"""

from scapy.all import rdpcap, wrpcap, sniff, IP, TCP, UDP, ICMP, ARP, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
import os
from datetime import datetime
from typing import List, Dict, Optional


class PacketCapture:
    """Manages packet capture file loading and basic operations"""
    
    def __init__(self):
        self.packets = []
        self.file_path = None
        self.packet_count = 0
        self.metadata = {}
    
    def load_pcap(self, file_path: str) -> bool:
        """
        Load PCAP file for analysis
        
        Args:
            file_path: Path to PCAP file
        
        Returns:
            Success status
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"PCAP file not found: {file_path}")
            
            print(f"[*] Loading PCAP file: {file_path}")
            self.packets = rdpcap(file_path)
            self.file_path = file_path
            self.packet_count = len(self.packets)
            
            # Extract metadata
            self.metadata = {
                'file_path': os.path.abspath(file_path),
                'file_name': os.path.basename(file_path),
                'file_size_bytes': os.path.getsize(file_path),
                'packet_count': self.packet_count,
                'loaded_timestamp': datetime.now().isoformat()
            }
            
            if self.packet_count > 0:
                first_packet_time = float(self.packets[0].time)
                last_packet_time = float(self.packets[-1].time)
                
                self.metadata.update({
                    'first_packet_time': datetime.fromtimestamp(first_packet_time).isoformat(),
                    'last_packet_time': datetime.fromtimestamp(last_packet_time).isoformat(),
                    'capture_duration_seconds': last_packet_time - first_packet_time
                })
            
            print(f"[+] Successfully loaded {self.packet_count} packets")
            return True
            
        except Exception as e:
            print(f"[!] Error loading PCAP file: {e}")
            return False
    
    def capture_live(self, interface: str = None, count: int = 100, 
                    timeout: int = 30, filter_str: str = None) -> bool:
        """
        Capture live network traffic (optional feature)
        
        Args:
            interface: Network interface (None = default)
            count: Number of packets to capture
            timeout: Capture timeout in seconds
            filter_str: BPF filter string
        
        Returns:
            Success status
        """
        try:
            print(f"[*] Starting live capture (count={count}, timeout={timeout}s)")
            if filter_str:
                print(f"[*] Filter: {filter_str}")
            
            self.packets = sniff(iface=interface, count=count, timeout=timeout, 
                               filter=filter_str, prn=lambda x: None)
            self.packet_count = len(self.packets)
            
            self.metadata = {
                'capture_type': 'live',
                'interface': interface or 'default',
                'packet_count': self.packet_count,
                'filter': filter_str,
                'capture_timestamp': datetime.now().isoformat()
            }
            
            print(f"[+] Captured {self.packet_count} packets")
            return True
            
        except Exception as e:
            print(f"[!] Error capturing live traffic: {e}")
            return False
    
    def save_pcap(self, output_file: str) -> bool:
        """
        Save packets to PCAP file
        
        Args:
            output_file: Output file path
        
        Returns:
            Success status
        """
        try:
            wrpcap(output_file, self.packets)
            print(f"[+] Packets saved to: {output_file}")
            return True
        except Exception as e:
            print(f"[!] Error saving PCAP: {e}")
            return False
    
    def filter_packets(self, filter_func) -> List:
        """
        Filter packets using custom function
        
        Args:
            filter_func: Function that returns True for packets to keep
        
        Returns:
            List of filtered packets
        """
        return [pkt for pkt in self.packets if filter_func(pkt)]
    
    def get_packet_summary(self, packet_index: int) -> str:
        """Get summary of specific packet"""
        if 0 <= packet_index < self.packet_count:
            return self.packets[packet_index].summary()
        return "Invalid packet index"
    
    def get_metadata(self) -> Dict:
        """Get capture metadata"""
        return self.metadata
    
    def get_packets(self) -> List:
        """Get all loaded packets"""
        return self.packets
    
    def get_packet_count(self) -> int:
        """Get total packet count"""
        return self.packet_count


if __name__ == "__main__":
    # Example usage
    print("Packet Capture Module - Testing")
    print("=" * 70)
    
    # Example: Load a PCAP file
    # capture = PacketCapture()
    # capture.load_pcap("sample.pcap")
    # print(f"Loaded {capture.get_packet_count()} packets")
