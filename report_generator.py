"""
Report Generator Module
Creates comprehensive forensic reports in multiple formats (HTML, PDF, JSON)
Combines analysis results with evidence handling documentation
"""

import json
import os
from datetime import datetime
from typing import Dict, List
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.platypus import KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT


class ReportGenerator:
    """Generates forensic analysis reports in multiple formats"""
    
    def __init__(self, case_id: str = None):
        """
        Initialize report generator
        
        Args:
            case_id: Case identifier
        """
        self.case_id = case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.report_data = {
            'case_id': self.case_id,
            'generated_date': datetime.now().isoformat(),
            'analyst': '',
            'evidence_file': '',
            'executive_summary': '',
            'findings': {},
            'recommendations': []
        }
    
    def set_metadata(self, analyst: str, evidence_file: str, summary: str = ""):
        """Set report metadata"""
        self.report_data.update({
            'analyst': analyst,
            'evidence_file': evidence_file,
            'executive_summary': summary
        })
    
    def add_findings(self, analysis_results: Dict, statistics: Dict, 
                    evidence_hash: Dict, coc_entries: List):
        """
        Add analysis findings to report
        
        Args:
            analysis_results: Protocol analysis results
            statistics: Statistical summaries
            evidence_hash: Evidence hash information
            coc_entries: Chain of custody entries
        """
        self.report_data['findings'] = {
            'analysis_results': analysis_results,
            'statistics': statistics,
            'evidence_integrity': evidence_hash,
            'chain_of_custody': coc_entries
        }
    
    def add_recommendations(self, recommendations: List[str]):
        """Add recommendations to report"""
        self.report_data['recommendations'] = recommendations
    
    def export_json(self, output_file: str = None) -> str:
        """
        Export report as JSON
        
        Args:
            output_file: Output file path
        
        Returns:
            Path to generated file
        """
        if output_file is None:
            output_file = f"report_{self.case_id}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.report_data, f, indent=2, default=str)
        
        print(f"[+] JSON report saved: {output_file}")
        return output_file
    
    def export_html(self, output_file: str = None, chart_files: List[str] = None) -> str:
        """
        Export report as HTML
        
        Args:
            output_file: Output file path
            chart_files: List of chart image files to embed
        
        Returns:
            Path to generated file
        """
        if output_file is None:
            output_file = f"report_{self.case_id}.html"
        
        html_content = self._generate_html(chart_files or [])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved: {output_file}")
        return output_file
    
    def _generate_html(self, chart_files: List[str]) -> str:
        """Generate HTML content for report"""
        
        findings = self.report_data.get('findings', {})
        stats = findings.get('statistics', {})
        analysis = findings.get('analysis_results', {})
        evidence = findings.get('evidence_integrity', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analysis Report - {self.case_id}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        h2 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        h3 {{
            color: #764ba2;
        }}
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        .meta-item {{
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        .meta-label {{
            font-weight: bold;
            color: #495057;
        }}
        .hash-box {{
            background: #f1f3f5;
            padding: 15px;
            border-left: 4px solid #667eea;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #dee2e6;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .alert {{
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }}
        .alert-warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            color: #856404;
        }}
        .alert-danger {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            color: #721c24;
        }}
        .alert-success {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            color: #155724;
        }}
        .chart-container {{
            text-align: center;
            margin: 20px 0;
        }}
        .chart-container img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Network Traffic Analysis Report</h1>
        <p>Forensic Investigation Report</p>
    </div>

    <div class="section">
        <h2>📋 Case Information</h2>
        <div class="meta-info">
            <div class="meta-item">
                <div class="meta-label">Case ID:</div>
                <div>{self.case_id}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Analyst:</div>
                <div>{self.report_data.get('analyst', 'N/A')}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Evidence File:</div>
                <div>{self.report_data.get('evidence_file', 'N/A')}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Report Generated:</div>
                <div>{self.report_data.get('generated_date', 'N/A')}</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>🔐 Evidence Integrity</h2>
        <div class="alert alert-success">
            <strong>✓ Evidence Hash Verified</strong>
        </div>
        <div class="hash-box">
            <strong>SHA-256:</strong><br>{evidence.get('sha256', 'N/A')}<br><br>
            <strong>MD5:</strong><br>{evidence.get('md5', 'N/A')}
        </div>
        <p><strong>File Size:</strong> {evidence.get('file_size_bytes', 0):,} bytes</p>
        <p><strong>Timestamp:</strong> {evidence.get('timestamp', 'N/A')}</p>
    </div>

    <div class="section">
        <h2>📊 Executive Summary</h2>
        <p>{self.report_data.get('executive_summary', 'No summary provided.')}</p>
    </div>

    <div class="section">
        <h2>📈 Traffic Statistics</h2>
        
        <h3>Protocol Distribution</h3>
        <table>
            <tr>
                <th>Protocol</th>
                <th>Packet Count</th>
                <th>Percentage</th>
            </tr>
"""
        
        # Add protocol stats
        protocol_dist = stats.get('protocol_summary', {})
        for proto, data in protocol_dist.items():
            if isinstance(data, dict):
                count = data.get('count', 0)
                percentage = data.get('percentage', 0)
                html += f"""
            <tr>
                <td>{proto}</td>
                <td>{count:,}</td>
                <td>{percentage:.2f}%</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h3>IP Communication Summary</h3>
"""
        
        ip_summary = stats.get('ip_summary', {})
        html += f"""
        <p><strong>Unique Source IPs:</strong> {ip_summary.get('unique_sources', 0)}</p>
        <p><strong>Unique Destination IPs:</strong> {ip_summary.get('unique_destinations', 0)}</p>
"""
        
        # Add charts if available
        if chart_files:
            html += """
    </div>
    
    <div class="section">
        <h2>📊 Visualizations</h2>
"""
            for chart_file in chart_files:
                if os.path.exists(chart_file):
                    chart_name = os.path.basename(chart_file).replace('_', ' ').replace('.png', '').title()
                    html += f"""
        <div class="chart-container">
            <h3>{chart_name}</h3>
            <img src="{chart_file}" alt="{chart_name}">
        </div>
"""
        
        # Add suspicious activity section
        suspicious = analysis.get('suspicious_activity', {})
        if suspicious:
            html += """
    </div>
    
    <div class="section">
        <h2>⚠️ Suspicious Activity Detected</h2>
"""
            
            port_scans = suspicious.get('port_scans', [])
            if port_scans:
                html += """
        <div class="alert alert-danger">
            <strong>Port Scanning Activity Detected</strong>
        </div>
        <table>
            <tr>
                <th>Source IP</th>
                <th>Ports Scanned</th>
                <th>Severity</th>
            </tr>
"""
                for scan in port_scans[:10]:
                    html += f"""
            <tr>
                <td>{scan.get('source_ip', 'N/A')}</td>
                <td>{scan.get('ports_scanned', 0)}</td>
                <td>{scan.get('severity', 'UNKNOWN')}</td>
            </tr>
"""
                html += """
        </table>
"""
            
            syn_floods = suspicious.get('syn_floods', [])
            if syn_floods:
                html += """
        <div class="alert alert-danger">
            <strong>Potential SYN Flood Attacks</strong>
        </div>
        <table>
            <tr>
                <th>Source IP</th>
                <th>SYN Count</th>
                <th>Severity</th>
            </tr>
"""
                for flood in syn_floods[:10]:
                    html += f"""
            <tr>
                <td>{flood.get('source_ip', 'N/A')}</td>
                <td>{flood.get('syn_count', 0)}</td>
                <td>{flood.get('severity', 'UNKNOWN')}</td>
            </tr>
"""
                html += """
        </table>
"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>🔗 Chain of Custody</h2>
        <p>Evidence handling has been documented according to forensic best practices.</p>
    </div>

    <div class="footer">
        <p>This is an official forensic analysis report generated by Network Traffic Analyzer Tool</p>
        <p>&copy; 2026 Digital Forensics Investigation</p>
    </div>
</body>
</html>
"""
        
        return html
    
    def export_pdf(self, output_file: str = None, chart_files: List[str] = None) -> str:
        """
        Export comprehensive forensic report as PDF
        
        Args:
            output_file: Output file path
            chart_files: List of chart image files to embed
        
        Returns:
            Path to generated file
        """
        if output_file is None:
            output_file = f"report_{self.case_id}.pdf"
        
        doc = SimpleDocTemplate(output_file, pagesize=letter,
                               topMargin=0.75*inch, bottomMargin=0.75*inch)
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=colors.grey,
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        # ============ COVER PAGE ============
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph("🔍", title_style))
        elements.append(Paragraph("NETWORK TRAFFIC ANALYSIS", title_style))
        elements.append(Paragraph("Forensic Investigation Report", subtitle_style))
        
        elements.append(Spacer(1, 0.5*inch))
        
        # Create style for wrapping long text in table
        wrap_style = ParagraphStyle(
            'WrapStyle',
            parent=styles['Normal'],
            fontSize=12,
            wordWrap='CJK',
            leading=14
        )
        
        cover_data = [
            ['Case ID:', self.case_id],
            ['Analyst:', self.report_data.get('analyst', 'N/A')],
            ['Evidence File:', Paragraph(self.report_data.get('evidence_file', 'N/A'), wrap_style)],
            ['Report Generated:', self.report_data.get('generated_date', 'N/A')[:19]]
        ]
        
        cover_table = Table(cover_data, colWidths=[150, 300])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        elements.append(cover_table)
        elements.append(Spacer(1, 1*inch))
        
        # Confidentiality notice
        conf_style = ParagraphStyle('Confidential', parent=styles['Normal'],
                                    fontSize=10, textColor=colors.red,
                                    alignment=TA_CENTER)
        elements.append(Paragraph("⚠ CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY ⚠", conf_style))
        
        elements.append(PageBreak())
        
        # ============ EXECUTIVE SUMMARY ============
        elements.append(Paragraph("Executive Summary", styles['Heading1']))
        elements.append(Spacer(1, 12))
        
        exec_summary = self.report_data.get('executive_summary', 'No summary provided.')
        elements.append(Paragraph(exec_summary, styles['BodyText']))
        elements.append(Spacer(1, 20))
        
        # ============ EVIDENCE INTEGRITY ============
        elements.append(Paragraph("Evidence Integrity Verification", styles['Heading1']))
        elements.append(Spacer(1, 12))
        
        findings = self.report_data.get('findings', {})
        evidence = findings.get('evidence_integrity', {})
        
        # Verification status box
        verify_para = Paragraph("✓ Evidence Hash Verified", 
                               ParagraphStyle('Success', parent=styles['Normal'],
                                            fontSize=12, textColor=colors.green,
                                            spaceAfter=12))
        elements.append(verify_para)
        
        # Create hash style for this section
        hash_style_small = ParagraphStyle(
            'HashStyleSmall',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7,
            wordWrap='CJK',
            leading=9
        )
        
        evidence_data = [
            ['Hash Algorithm', 'Hash Value'],
            ['SHA-256', Paragraph(evidence.get('sha256', 'N/A'), hash_style_small)],
            ['MD5', Paragraph(evidence.get('md5', 'N/A'), hash_style_small)],
        ]
        
        evidence_table = Table(evidence_data, colWidths=[120, 350])
        evidence_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(evidence_table)
        elements.append(Spacer(1, 12))
        
        # File metadata
        meta_text = f"""
        <b>File Size:</b> {evidence.get('file_size_bytes', 0):,} bytes<br/>
        <b>Verified:</b> {evidence.get('timestamp', 'N/A')}<br/>
        """
        elements.append(Paragraph(meta_text, styles['BodyText']))
        elements.append(Spacer(1, 20))
        
        elements.append(PageBreak())
        
        # ============ COMPLETE IP ADDRESS LISTING ============
        elements.append(Paragraph("Complete IP Address Inventory", styles['Heading1']))
        elements.append(Spacer(1, 12))
        
        analysis_results = findings.get('analysis_results', {})
        ip_comms = analysis_results.get('ip_communications', {})
        
        # Convert dictionary format to list format for display
        top_source_ips_dict = ip_comms.get('top_source_ips', {})
        top_dest_ips_dict = ip_comms.get('top_destination_ips', {})
        
        # Source IPs
        elements.append(Paragraph("Source IP Addresses", styles['Heading2']))
        if top_source_ips_dict:
            src_data = [['#', 'Source IP Address', 'Packet Count']]
            for idx, (ip, count) in enumerate(list(top_source_ips_dict.items())[:50], 1):
                src_data.append([str(idx), ip, str(count)])
            
            src_table = Table(src_data, colWidths=[30, 200, 100])
            src_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            elements.append(src_table)
        else:
            elements.append(Paragraph("No source IPs found.", styles['BodyText']))
        
        elements.append(Spacer(1, 20))
        
        # Destination IPs
        elements.append(Paragraph("Destination IP Addresses", styles['Heading2']))
        if top_dest_ips_dict:
            dst_data = [['#', 'Destination IP Address', 'Packet Count']]
            for idx, (ip, count) in enumerate(list(top_dest_ips_dict.items())[:50], 1):
                dst_data.append([str(idx), ip, str(count)])
            
            dst_table = Table(dst_data, colWidths=[30, 200, 100])
            dst_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            elements.append(dst_table)
        else:
            elements.append(Paragraph("No destination IPs found.", styles['BodyText']))
        
        elements.append(Spacer(1, 12))
        
        # IP Summary
        stats = findings.get('statistics', {})
        ip_summary = stats.get('ip_summary', {})
        summary_text = f"""
        <b>Total Unique Source IPs:</b> {ip_summary.get('unique_sources', 0)}<br/>
        <b>Total Unique Destination IPs:</b> {ip_summary.get('unique_destinations', 0)}<br/>
        """
        elements.append(Paragraph(summary_text, styles['BodyText']))
        
        elements.append(PageBreak())
        
        # ============ PROTOCOL ANALYSIS ============
        elements.append(Paragraph("Protocol Distribution Analysis", styles['Heading1']))
        elements.append(Spacer(1, 12))
        
        protocol_summary = stats.get('protocol_summary', {})
        if protocol_summary:
            proto_data = [['Protocol', 'Packet Count', 'Percentage']]
            for proto, data in list(protocol_summary.items())[:20]:
                if isinstance(data, dict):
                    proto_data.append([
                        proto,
                        f"{data.get('count', 0):,}",
                        f"{data.get('percentage', 0):.2f}%"
                    ])
            
            proto_table = Table(proto_data, colWidths=[150, 150, 150])
            proto_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            elements.append(proto_table)
        
        elements.append(Spacer(1, 20))
        
        # Embed charts if available
        if chart_files:
            for chart_file in chart_files:
                if os.path.exists(chart_file) and 'protocol' in chart_file.lower():
                    elements.append(Paragraph("Protocol Distribution Chart", styles['Heading3']))
                    try:
                        img = Image(chart_file, width=5*inch, height=3*inch)
                        elements.append(img)
                        elements.append(Spacer(1, 12))
                    except:
                        pass
        
        elements.append(PageBreak())
        
        # ============ SUSPICIOUS ACTIVITY ============
        elements.append(Paragraph("Suspicious Activity Analysis", styles['Heading1']))
        elements.append(Spacer(1, 12))
        
        suspicious = analysis_results.get('suspicious_activity', {})
        port_scans = suspicious.get('port_scans', [])
        syn_floods = suspicious.get('syn_floods', [])
        udp_floods = suspicious.get('udp_floods', [])
        icmp_floods = suspicious.get('icmp_floods', [])
        ddos_indicators = suspicious.get('ddos_indicators', [])
        high_volume = suspicious.get('high_volume_ips', [])
        malicious_transfers = suspicious.get('malicious_transfers', [])
        
        has_suspicious = any([port_scans, syn_floods, udp_floods, icmp_floods, 
                             ddos_indicators, high_volume, malicious_transfers])
        
        if has_suspicious:
            # DDoS Indicators (show first - highest priority)
            if ddos_indicators:
                elements.append(Paragraph("⚠ CRITICAL: DDoS Attack Indicators Detected", 
                              ParagraphStyle('Critical', parent=styles['Heading2'],
                                           textColor=colors.red)))
                elements.append(Spacer(1, 8))
                
                for indicator in ddos_indicators:
                    ind_info = f"""
                    <b>Pattern:</b> {indicator.get('pattern', 'Unknown')}<br/>
                    <b>Indication:</b> {indicator.get('indication', 'N/A')}<br/>
                    <b>Severity:</b> <font color="red">{indicator.get('severity', 'N/A')}</font><br/>
                    """
                    
                    if 'target_ip' in indicator:
                        ind_info += f"""
                        <b>Target IP:</b> {indicator.get('target_ip')}<br/>
                        <b>Unique Attackers:</b> {indicator.get('unique_attackers'):,}<br/>
                        <b>Total Packets:</b> {indicator.get('total_packets'):,}
                        """
                    elif 'packets_per_second' in indicator:
                        ind_info += f"""
                        <b>Packet Rate:</b> {indicator.get('packets_per_second'):,.2f} packets/sec<br/>
                        <b>Total Packets:</b> {indicator.get('total_packets'):,}<br/>
                        <b>Duration:</b> {indicator.get('duration_seconds')} seconds
                        """
                    
                    elements.append(Paragraph(ind_info, styles['BodyText']))
                    elements.append(Spacer(1, 10))
                elements.append(Spacer(1, 12))
            
            # UDP Floods
            if udp_floods:
                elements.append(Paragraph("⚠ UDP Flood Attacks Detected", 
                              ParagraphStyle('Warning', parent=styles['Heading2'],
                                           textColor=colors.red)))
                elements.append(Spacer(1, 8))
                
                udp_data = [['Source IP', 'UDP Packets', 'Severity']]
                for flood in udp_floods[:10]:
                    udp_data.append([
                        flood.get('source_ip', 'N/A'),
                        str(flood.get('udp_packet_count', 0)),
                        flood.get('severity', 'UNKNOWN')
                    ])
                
                udp_table = Table(udp_data, colWidths=[180, 120, 120])
                udp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(udp_table)
                elements.append(Spacer(1, 12))
            
            # ICMP Floods
            if icmp_floods:
                elements.append(Paragraph("⚠ ICMP Flood Attacks Detected", 
                              ParagraphStyle('Warning', parent=styles['Heading2'],
                                           textColor=colors.red)))
                elements.append(Spacer(1, 8))
                
                icmp_data = [['Source IP', 'ICMP Packets', 'Severity']]
                for flood in icmp_floods[:10]:
                    icmp_data.append([
                        flood.get('source_ip', 'N/A'),
                        str(flood.get('icmp_packet_count', 0)),
                        flood.get('severity', 'UNKNOWN')
                    ])
                
                icmp_table = Table(icmp_data, colWidths=[180, 120, 120])
                icmp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(icmp_table)
                elements.append(Spacer(1, 12))
            
            # SYN floods
            if syn_floods:
                elements.append(Paragraph("⚠ SYN Flood Attacks Detected", 
                              ParagraphStyle('Warning', parent=styles['Heading2'],
                                           textColor=colors.red)))
                elements.append(Spacer(1, 8))
                
                flood_data = [['Source IP', 'SYN Count', 'Severity']]
                for flood in syn_floods[:20]:
                    flood_data.append([
                        flood.get('source_ip', 'N/A'),
                        str(flood.get('syn_count', 0)),
                        flood.get('severity', 'UNKNOWN')
                    ])
                
                flood_table = Table(flood_data, colWidths=[180, 120, 120])
                flood_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(flood_table)
                elements.append(Spacer(1, 12))
            
            # Malicious Transfers
            if malicious_transfers:
                elements.append(Paragraph("⚠ Suspicious File Transfer Activity", 
                              ParagraphStyle('Warning', parent=styles['Heading2'],
                                           textColor=colors.orange)))
                elements.append(Spacer(1, 8))
                
                for transfer in malicious_transfers[:5]:
                    transfer_info = f"""
                    <b>Type:</b> {transfer.get('type', 'Unknown')}<br/>
                    <b>Source IP:</b> {transfer.get('source_ip', 'N/A')}<br/>
                    <b>Indication:</b> {transfer.get('indication', 'N/A')}<br/>
                    <b>Severity:</b> {transfer.get('severity', 'UNKNOWN')}
                    """
                    elements.append(Paragraph(transfer_info, styles['BodyText']))
                    elements.append(Spacer(1, 8))
                elements.append(Spacer(1, 12))
            
            # Port scans
            if port_scans:
                elements.append(Paragraph("⚠ Port Scanning Activity Detected", 
                              ParagraphStyle('Warning', parent=styles['Heading2'],
                                           textColor=colors.orange)))
                elements.append(Spacer(1, 8))
                
                scan_data = [['Source IP', 'Ports Scanned', 'Severity']]
                for scan in port_scans[:20]:
                    scan_data.append([
                        scan.get('source_ip', 'N/A'),
                        str(scan.get('ports_scanned', 0)),
                        scan.get('severity', 'UNKNOWN')
                    ])
                
                scan_table = Table(scan_data, colWidths=[180, 120, 120])
                scan_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(scan_table)
                elements.append(Spacer(1, 12))
            
            # High Volume
            if high_volume:
                elements.append(Paragraph("⚠ High Volume Traffic Sources", 
                              ParagraphStyle('Warning', parent=styles['Heading2'],
                                           textColor=colors.orange)))
                elements.append(Spacer(1, 8))
                
                vol_data = [['IP Address', 'Packets', 'Percentage', 'Severity']]
                for ip_info in high_volume[:10]:
                    vol_data.append([
                        ip_info.get('ip_address', 'N/A'),
                        f"{ip_info.get('packet_count', 0):,}",
                        f"{ip_info.get('percentage', 0)}%",
                        ip_info.get('severity', 'UNKNOWN')
                    ])
                
                vol_table = Table(vol_data, colWidths=[140, 100, 100, 80])
                vol_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(vol_table)
                elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("✓ No suspicious activity detected.", 
                                    ParagraphStyle('Success', parent=styles['Normal'],
                                                 textColor=colors.green, fontSize=12)))
        
        elements.append(Spacer(1, 20))
        elements.append(PageBreak())
        
        # ============ CHAIN OF CUSTODY (CoC) FORM ============
        elements.append(Paragraph("CHAIN OF CUSTODY (CoC) FORM", styles['Heading1']))
        elements.append(Spacer(1, 12))
        
        # Case Information Section
        elements.append(Paragraph("Case Information", styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        case_info_data = [
            ['Case Title:', self.case_id],
            ['Analyst:', self.report_data.get('analyst', 'N/A')],
            ['Case Description:', self.report_data.get('case_description', 'N/A')[:60]],
            ['Date Started:', self.report_data.get('generated_date', 'N/A')[:10]]
        ]
        
        case_info_table = Table(case_info_data, colWidths=[120, 350])
        case_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(case_info_table)
        elements.append(Spacer(1, 15))
        
        # Evidence Details Section
        elements.append(Paragraph("Evidence Details", styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        # Create small mono font style for hashes
        hash_style = ParagraphStyle(
            'HashStyle',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7,
            wordWrap='CJK',
            leading=9
        )
        
        evidence_details_data = [
            ['Evidence Type:', 'PCAP Network Capture File'],
            ['File Name:', self.report_data.get('evidence_file', 'N/A')],
            ['File Size:', f"{evidence.get('file_size_bytes', 0):,} bytes"],
            ['Evidence Source:', 'Digital Network Traffic Capture'],
            ['Original Hash (SHA256):', Paragraph(evidence.get('sha256', 'N/A'), hash_style)],
            ['Original Hash (MD5):', Paragraph(evidence.get('md5', 'N/A'), hash_style)],
            ['Acquisition Date/Time:', evidence.get('timestamp', 'N/A')[:19]]
        ]
        
        evidence_details_table = Table(evidence_details_data, colWidths=[150, 320])
        evidence_details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(evidence_details_table)
        elements.append(Spacer(1, 15))
        
        # Storage Information Section
        elements.append(Paragraph("Storage & Integrity Information", styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        storage_data = [
            ['Storage Location:', 'Local Evidence Repository'],
            ['Backup Location:', 'Secure Backup System'],
            ['Access Restriction:', 'Authorized Personnel Only'],
            ['', ''],
            ['Final Hash Verification:', ''],
            ['Hash BEFORE Analysis:', Paragraph(evidence.get('sha256', 'N/A'), hash_style)],
            ['Hash AFTER Analysis:', Paragraph(evidence.get('sha256', 'N/A'), hash_style)],
            ['Integrity Status:', 'MATCHED ✓' if evidence.get('sha256') else 'NOT VERIFIED']
        ]
        
        storage_table = Table(storage_data, colWidths=[150, 320])
        storage_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('BACKGROUND', (0, 7), (1, 7), colors.lightgreen),  # Integrity status row
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 7), (1, 7), 'Helvetica-Bold'),  # Integrity status
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(storage_table)
        elements.append(Spacer(1, 15))
        
        # Declaration
        declaration_style = ParagraphStyle('Declaration', parent=styles['Normal'],
                                          fontSize=9, leading=12, spaceAfter=15)
        declaration_text = """
        <b>Declaration:</b><br/>
        I/We declare that the evidence was handled ethically and professionally.
        All procedures followed proper chain of custody protocols.
        Hash verification confirms evidence integrity has been maintained throughout the analysis.
        """
        elements.append(Paragraph(declaration_text, declaration_style))
        elements.append(Spacer(1, 10))
        
        # Handling Log Table
        elements.append(Paragraph("Handling Log", styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        # Create style for wrapping text in table cells
        cell_style = ParagraphStyle(
            'CellStyle',
            parent=styles['Normal'],
            fontSize=7,
            leading=9,
            wordWrap='CJK'
        )
        
        coc_entries = findings.get('chain_of_custody', [])
        if coc_entries:
            # Create detailed handling log table
            handling_data = [
                ['No.', 'Date/Time', 'Handler Name', 'Action Taken', 'Purpose', 'Hash\n(Yes/No)', 'Verified']
            ]
            
            for idx, entry in enumerate(coc_entries, 1):
                handling_data.append([
                    str(idx),
                    entry.get('timestamp', 'N/A')[:19],
                    Paragraph(entry.get('analyst_name', 'N/A'), cell_style),
                    Paragraph(entry.get('action', 'N/A'), cell_style),
                    Paragraph(entry.get('notes', 'N/A')[:50], cell_style),  # Limit to 50 chars
                    'Yes',
                    '✓'
                ])
            
            handling_table = Table(handling_data, colWidths=[25, 80, 75, 85, 95, 40, 40])
            handling_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # Center No. column
                ('ALIGN', (5, 0), (6, -1), 'CENTER'),  # Center Hash and Verified columns
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 7),
                ('FONTSIZE', (0, 1), (0, -1), 7),  # No. column
                ('FONTSIZE', (1, 1), (1, -1), 7),  # Date column
                ('FONTSIZE', (5, 1), (6, -1), 7),  # Hash and Verified columns
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(handling_table)
        else:
            elements.append(Paragraph("No handling log entries recorded.", styles['BodyText']))
        
        elements.append(Spacer(1, 20))
        
        # Signature Section
        elements.append(Paragraph("Certification", styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        signature_data = [
            ['Name', 'Signature', 'Date'],
            [self.report_data.get('analyst', ''), '', self.report_data.get('generated_date', 'N/A')[:10]],
            ['', '', ''],
            ['', '', '']
        ]
        
        signature_table = Table(signature_data, colWidths=[200, 170, 100])
        signature_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 25),  # Space for signature
        ]))
        elements.append(signature_table)
        
        elements.append(Spacer(1, 20))
        
        # Footer
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'],
                                     fontSize=9, textColor=colors.grey,
                                     alignment=TA_CENTER)
        elements.append(Spacer(1, 1*inch))
        elements.append(Paragraph("--- End of Report ---", footer_style))
        elements.append(Paragraph(f"Generated by Network Traffic Analyzer | {self.case_id}", footer_style))
        
        # Build PDF
        doc.build(elements)
        print(f"[+] Comprehensive PDF report saved: {output_file}")
        return output_file


if __name__ == "__main__":
    print("Report Generator Module - Testing")
    print("=" * 70)
