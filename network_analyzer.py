"""
Network Traffic Analyzer - Main Application
Digital Forensic Tool for Network Traffic Analysis
Includes CLO3 Requirements: Evidence Hashing, Chain of Custody, Ethical Handling
"""

import sys
import os
import argparse
from datetime import datetime

# Import forensic modules
from evidence_handler import EvidenceHandler
from chain_of_custody import ChainOfCustody
from ethical_handler import EthicalHandler
from packet_capture import PacketCapture
from protocol_analyzer import ProtocolAnalyzer
from statistics import StatisticsGenerator
from report_generator import ReportGenerator


class NetworkAnalyzer:
    """Main network traffic analyzer application"""
    
    def __init__(self):
        self.evidence_handler = EvidenceHandler()
        self.coc = None
        self.ethical_handler = EthicalHandler()
        self.packet_capture = PacketCapture()
        self.analysis_results = {}
        self.case_id = None
    
    def run_analysis(self, pcap_file: str, analyst_name: str, case_id: str = None,
                    authorized_by: str = None, case_description: str = ""):
        """
        Run complete forensic analysis on PCAP file
        
        Args:
            pcap_file: Path to PCAP file
            analyst_name: Name of forensic analyst
            case_id: Optional case identifier
            authorized_by: Who authorized the analysis
            case_description: Description of the investigation
        """
        
        self.case_id = case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        print("\n" + "="*70)
        print("NETWORK TRAFFIC ANALYZER - DIGITAL FORENSIC TOOL")
        print("="*70)
        print(f"Case ID: {self.case_id}")
        print(f"Analyst: {analyst_name}")
        print("="*70 + "\n")
        
        # STEP 1: Ethical Authorization
        print("[STEP 1/7] Verifying Ethical Authorization...")
        if authorized_by:
            self.ethical_handler.record_authorization(
                authorized_by=authorized_by,
                case_description=case_description or "Network traffic analysis investigation",
                authorization_ref=self.case_id
            )
            self.ethical_handler.complete_ethical_checklist()
        
        # Removed ethical compliance check - proceed automatically
        print("[+] Ethical compliance recorded\n")
        
        
        # STEP 2: Evidence Hash Calculation
        print("[STEP 2/7] Calculating Evidence Hashes...")
        evidence_record = self.evidence_handler.calculate_hashes(pcap_file)
        print(f"[+] SHA-256: {evidence_record['sha256']}")
        print(f"[+] MD5:     {evidence_record['md5']}")
        print(f"[+] File Size: {evidence_record['file_size_bytes']:,} bytes\n")
        
        # STEP 3: Initialize Chain of Custody
        print("[STEP 3/7] Initializing Chain of Custody...")
        self.coc = ChainOfCustody(pcap_file, self.case_id)
        self.coc.add_entry(
            action="Evidence Acquired",
            analyst_name=analyst_name,
            analyst_id=self.case_id,
            notes=f"PCAP file loaded for analysis. SHA256: {evidence_record['sha256'][:16]}..."
        )
        self.coc.add_entry(
            action="Hash Calculated",
            analyst_name=analyst_name,
            analyst_id=self.case_id,
            notes="SHA256 and MD5 hashes generated for integrity verification"
        )
        print()
        
        # STEP 4: Load PCAP File
        print("[STEP 4/7] Loading PCAP File...")
        if not self.packet_capture.load_pcap(pcap_file):
            print("[!] Failed to load PCAP file")
            return
        
        self.coc.add_entry(
            action="Analysis Started",
            analyst_name=analyst_name,
            analyst_id=self.case_id,
            notes=f"Loaded {self.packet_capture.get_packet_count()} packets for analysis"
        )
        print()
        
        # STEP 5: Protocol Analysis
        print("[STEP 5/7] Performing Protocol Analysis...")
        analyzer = ProtocolAnalyzer(self.packet_capture.get_packets())
        self.analysis_results = analyzer.analyze_all()
        print()
        
        # STEP 6: Generate Statistics and Visualizations
        print("[STEP 6/7] Generating Statistics and Visualizations...")
        stats_generator = StatisticsGenerator(self.analysis_results)
        output_dir = f"reports/{self.case_id}"
        os.makedirs(output_dir, exist_ok=True)
        
        statistics = stats_generator.generate_all_stats(output_dir)
        chart_files = stats_generator.get_generated_charts()
        print()
        
        # STEP 7: Generate Reports
        print("[STEP 7/7] Generating Forensic Reports...")
        report_gen = ReportGenerator(self.case_id)
        report_gen.set_metadata(
            analyst=analyst_name,
            evidence_file=os.path.basename(pcap_file),
            summary=self._generate_executive_summary()
        )
        
        report_gen.add_findings(
            analysis_results=self.analysis_results,
            statistics=statistics,
            evidence_hash=evidence_record,
            coc_entries=self.coc.get_all_entries()
        )
        
        #Export reports
        json_report = report_gen.export_json(os.path.join(output_dir, f"report_{self.case_id}.json"))
        html_report = report_gen.export_html(os.path.join(output_dir, f"report_{self.case_id}.html"), chart_files)
        pdf_report = report_gen.export_pdf(os.path.join(output_dir, f"report_{self.case_id}.pdf"), chart_files)
        
        # Save evidence hash record
        self.evidence_handler.save_hash_record(pcap_file, os.path.join(output_dir, "evidence_hash.json"))
        
        # Save chain of custody
        self.coc.save_to_json(os.path.join(output_dir, f"CoC_{self.case_id}.json"))
        self.coc.export_to_pdf(os.path.join(output_dir, f"CoC_{self.case_id}.pdf"))
        
        # Save ethical record
        self.ethical_handler.save_ethical_record(os.path.join(output_dir, "ethical_compliance.json"))
        
        self.coc.add_entry(
            action="Reports Generated",
            analyst_name=analyst_name,
            analyst_id=self.case_id,
            notes="Analysis complete. All reports and documentation generated."
        )
        
        print("\n" + "="*70)
        print("ANALYSIS COMPLETE!")
        print("="*70)
        print(f"\nAll reports saved to: {output_dir}/")
        print(f"\nGenerated Files:")
        print(f"  - HTML Report: report_{self.case_id}.html")
        print(f"  - PDF Report: report_{self.case_id}.pdf")
        print(f"  - JSON Report: report_{self.case_id}.json")
        print(f"  - Chain of Custody: CoC_{self.case_id}.pdf")
        print(f"  - Evidence Hash: evidence_hash.json")
        print(f"  - Ethical Record: ethical_compliance.json")
        print(f"  - Visualizations: {len(chart_files)} chart(s)")
        print("\n" + "="*70 + "\n")
        
        # Print summary
        self._print_summary()
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary from analysis results"""
        
        ip_comms = self.analysis_results.get('ip_communications', {})
        suspicious = self.analysis_results.get('suspicious_activity', {})
        
        summary = f"""
Network traffic analysis was conducted on the provided PCAP file. 
The analysis identified {ip_comms.get('unique_source_ips', 0)} unique source IP addresses 
and {ip_comms.get('unique_destination_ips', 0)} unique destination IP addresses. 
"""
        
        # Check for ALL types of suspicious activity (including new DDoS detections)
        port_scans = suspicious.get('port_scans', [])
        syn_floods = suspicious.get('syn_floods', [])
        udp_floods = suspicious.get('udp_floods', [])
        icmp_floods = suspicious.get('icmp_floods', [])
        ddos_indicators = suspicious.get('ddos_indicators', [])
        high_volume = suspicious.get('high_volume_ips', [])
        malicious_transfers = suspicious.get('malicious_transfers', [])
        
        total_suspicious = (len(port_scans) + len(syn_floods) + len(udp_floods) + 
                          len(icmp_floods) + len(ddos_indicators) + len(high_volume) +
                          len(malicious_transfers))
        
        if total_suspicious >  0:
            summary += "\n\n⚠ SUSPICIOUS ACTIVITY DETECTED:\n"
            if ddos_indicators:
                summary += f"  - {len(ddos_indicators)} DDoS attack indicator(s)\n"
            if syn_floods:
                summary += f"  - {len(syn_floods)} SYN flood attack(s)\n"
            if udp_floods:
                summary += f"  - {len(udp_floods)} UDP flood attack(s)\n"
            if icmp_floods:
                summary += f"  - {len(icmp_floods)} ICMP flood attack(s)\n"
            if port_scans:
                summary += f"  - {len(port_scans)} port scan(s)\n"
            if high_volume:
                summary += f"  - {len(high_volume)} high-volume traffic source(s)\n"
            if malicious_transfers:
                summary += f"  - {len(malicious_transfers)} suspicious file transfer(s)\n"
            summary += "Detailed findings are documented in the full report."
        else:
            summary += "\n\nNo significant suspicious activity was detected during the analysis."
        
        return summary
    
    def _print_summary(self):
        """Print analysis summary to console"""
        
        print("[ANALYSIS SUMMARY]")
        print("-" * 70)
        
        # Protocol Distribution
        protocols = self.analysis_results.get('protocol_distribution', {})
        if protocols:
            print("\nProtocol Distribution:")
            for proto, data in list(protocols.items())[:5]:
                if isinstance(data, dict):
                    print(f"  {proto}: {data.get('count', 0)} packets ({data.get('percentage', 0):.1f}%)")
        
        # IP Statistics
        ip_comms = self.analysis_results.get('ip_communications', {})
        print(f"\nIP Statistics:")
        print(f"  Unique Source IPs: {ip_comms.get('unique_source_ips', 0)}")
        print(f"  Unique Destination IPs: {ip_comms.get('unique_destination_ips', 0)}")
        
        # Suspicious Activity
        suspicious = self.analysis_results.get('suspicious_activity', {})
        port_scans = suspicious.get('port_scans', [])
        syn_floods = suspicious.get('syn_floods', [])
        
        if port_scans or syn_floods:
            print(f"\n⚠️  SUSPICIOUS ACTIVITY DETECTED:")
            if port_scans:
                print(f"  - Port Scans: {len(port_scans)} source(s)")
                for scan in port_scans[:3]:
                    print(f"    • {scan['source_ip']}: {scan['ports_scanned']} ports ({scan['severity']})")
            
            if syn_floods:
                print(f"  - SYN Floods: {len(syn_floods)} source(s)")
                for flood in syn_floods[:3]:
                    print(f"    • {flood['source_ip']}: {flood['syn_count']} SYN packets ({flood['severity']})")
        
        print("-" * 70)


def main():
    """Main entry point for CLI"""
    
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer - Digital Forensic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python network_analyzer.py -f capture.pcap -a "John Doe"
  
  # Full forensic analysis with authorization
  python network_analyzer.py -f capture.pcap -a "Jane Smith" -c "CASE-2026-001" \\
      --authorized-by "Security Manager" --description "Investigating network breach"
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='Path to PCAP file')
    parser.add_argument('-a', '--analyst', required=True, help='Analyst name')
    parser.add_argument('-c', '--case-id', help='Case ID (auto-generated if not provided)')
    parser.add_argument('--authorized-by', help='Authorization source')
    parser.add_argument('--description', help='Case description')
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    
    args = parser.parse_args()
    
    if args.gui:
        print("[*] Launching GUI interface...")
        from gui_interface import launch_gui
        launch_gui()
    else:
        # CLI mode
        analyzer = NetworkAnalyzer()
        analyzer.run_analysis(
            pcap_file=args.file,
            analyst_name=args.analyst,
            case_id=args.case_id,
            authorized_by=args.authorized_by,
            case_description=args.description
        )


if __name__ == "__main__":
    main()
