"""
Generate Project Documentation Report for Network Traffic Analyzer
Following ITT593 Academic Report Template
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os


def generate_project_documentation():
    """Generate comprehensive project documentation PDF"""
    
    output_file = "PROJECT_DOCUMENTATION_TEMPLATE.pdf"
    
    doc = SimpleDocTemplate(output_file, pagesize=letter,
                           topMargin=1*inch, bottomMargin=1*inch,
                           leftMargin=1*inch, rightMargin=1*inch)
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontSize=18,
        textColor=colors.black,
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#667eea'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.black,
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'BodyJustify',
        parent=styles['BodyText'],
        fontSize=11,
        alignment=TA_JUSTIFY,
        spaceAfter=12
    )
    
    # ============ TITLE PAGE ============
    elements.append(Spacer(1, 1*inch))
    
    elements.append(Paragraph("STUDENT REPORT TEMPLATE (ITT593)", title_style))
    elements.append(Spacer(1, 0.3*inch))
    
    elements.append(Paragraph("Network Traffic Analyzer", title_style))
    elements.append(Paragraph("Digital Forensic Tool", 
                             ParagraphStyle('Subtitle', parent=styles['Normal'],
                                          fontSize=14, alignment=TA_CENTER)))
    elements.append(Spacer(1, 0.5*inch))
    
    # Title page info table
    title_info = [
        ['Project Title:', 'Network Traffic Analyzer - Digital Forensic Tool'],
        ['Group Members:', '[Your Name(s) - Fill in]'],
        ['Course & Lecturer:', 'ITT593 - [Lecturer Name - Fill in]'],
        ['Date:', datetime.now().strftime('%B %Y')]
    ]
    
    title_table = Table(title_info, colWidths=[140, 300])
    title_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(title_table)
    
    elements.append(PageBreak())
    
    # ============ 2. ABSTRACT ============
    elements.append(Paragraph("2. Abstract", heading1_style))
    elements.append(Paragraph("""
    <b>Short summary of tool and findings:</b><br/><br/>
    
    This project presents a comprehensive Network Traffic Analyzer designed for digital forensic investigation. 
    The tool provides automated analysis of network packet capture (PCAP) files, implementing forensic best 
    practices including evidence integrity verification, chain of custody documentation, and ethical compliance 
    tracking. The system features both a graphical user interface and command-line interface, enabling investigators 
    to efficiently analyze network traffic, detect suspicious activities, and generate court-ready forensic reports.<br/><br/>
    
    <b>Key Features:</b> Evidence hashing (SHA-256/MD5), automated protocol analysis, suspicious activity detection 
    (port scanning, SYN floods), comprehensive IP address tracking, statistical visualizations, and professional 
    PDF report generation with integrated Chain of Custody documentation.<br/><br/>
    
    <b>Technologies Used:</b> Python, Scapy, TkinterDnD2, Matplotlib, ReportLab, PyShark
    """, body_style))
    
    elements.append(PageBreak())
    
    # ============ 3. INTRODUCTION ============
    elements.append(Paragraph("3. Introduction", heading1_style))
    
    elements.append(Paragraph("Background", heading2_style))
    elements.append(Paragraph("""
    Network forensics is a critical component of digital investigations, involving the capture, analysis, 
    and interpretation of network traffic data. With the increasing sophistication of cyber attacks and 
    the growing volume of network data, there is a pressing need for automated forensic tools that can 
    efficiently process PCAP files while maintaining proper chain of custody and evidence integrity standards.
    """, body_style))
    
    elements.append(Paragraph("Problem Statement", heading2_style))
    elements.append(Paragraph("""
    Current network analysis tools often lack comprehensive forensic documentation features, making it 
    difficult for investigators to maintain proper evidence handling procedures, generate court-admissible 
    reports, and ensure ethical compliance throughout the investigation process. Manual analysis is 
    time-consuming and prone to human error, while many existing tools do not provide automated suspicious 
    activity detection or proper chain of custody tracking.
    """, body_style))
    
    elements.append(Paragraph("Objective", heading2_style))
    objectives = """
    • Develop an automated network traffic analysis tool with forensic capabilities<br/>
    • Implement evidence integrity verification using cryptographic hashing<br/>
    • Provide automated detection of suspicious network activities<br/>
    • Generate comprehensive, court-ready forensic reports<br/>
    • Maintain proper chain of custody documentation<br/>
    • Create user-friendly GUI for ease of use<br/>
    • Ensure ethical compliance tracking throughout analysis process
    """
    elements.append(Paragraph(objectives, body_style))
    
    elements.append(Paragraph("Scope", heading2_style))
    elements.append(Paragraph("""
    This project focuses on post-capture analysis of network traffic data stored in PCAP format. 
    The scope includes protocol analysis (TCP, UDP, HTTP, DNS), IP communication tracking, 
    suspicious activity detection, statistical analysis, and comprehensive report generation. 
    The tool is designed for forensic investigators, security analysts, and educational purposes.
    """, body_style))
    
    elements.append(PageBreak())
    
    # ============ 4. LITERATURE REVIEW ============
    elements.append(Paragraph("4. Literature Review", heading1_style))
    
    elements.append(Paragraph("Similar Tools", heading2_style))
    similar_tools = """
    <b>Wireshark:</b> Industry-standard packet analyzer with extensive protocol support but lacks 
    automated forensic documentation and chain of custody features.<br/><br/>
    
    <b>NetworkMiner:</b> Forensic analysis tool focused on artifact extraction but limited in 
    automated suspicious activity detection and comprehensive reporting.<br/><br/>
    
    <b>tcpdump:</b> Command-line packet capture tool providing raw data access but requiring 
    extensive manual analysis and lacking forensic documentation capabilities.
    """
    elements.append(Paragraph(similar_tools, body_style))
    
    elements.append(Paragraph("Gaps Identified", heading2_style))
    gaps = """
    • Lack of integrated chain of custody documentation<br/>
    • Limited automated suspicious activity detection<br/>
    • Insufficient evidence integrity verification workflows<br/>
    • Missing ethical compliance tracking<br/>
    • Complex interfaces unsuitable for quick forensic triage<br/>
    • Absence of comprehensive, court-ready PDF report generation
    """
    elements.append(Paragraph(gaps, body_style))
    
    elements.append(PageBreak())
    
    # ============ 5. METHODOLOGY ============
    elements.append(Paragraph("5. Methodology", heading1_style))
    
    elements.append(Paragraph("Tool Architecture", heading2_style))
    architecture = """
    <b>Modular Design:</b><br/>
    • Evidence Handler Module - SHA-256/MD5 hashing, integrity verification<br/>
    • Chain of Custody Module - Entry tracking, PDF/JSON export<br/>
    • Ethical Compliance Module - Authorization and compliance checking<br/>
    • Packet Analysis Module - Scapy-based packet parsing<br/>
    • Protocol Analysis Module - TCP/UDP/HTTP/DNS protocol extraction<br/>
    • Statistics Module - Data aggregation and visualization<br/>
    • Suspicious Activity Detector - Port scan and SYN flood detection<br/>
    • Report Generator - Multi-format report creation (HTML, PDF, JSON)<br/>
    • GUI Interface - TkinterDnD2-based user interface with drag-and-drop
    """
    elements.append(Paragraph(architecture, body_style))
    
    elements.append(Paragraph("Libraries Used", heading2_style))
    libraries = """
    • <b>Scapy 2.5.0+</b> - Packet manipulation and analysis<br/>
    • <b>PyShark 0.6+</b> - Alternative packet parsing using tshark<br/>
    • <b>Matplotlib 3.5.0+</b> - Statistical visualizations and charts<br/>
    • <b>Pandas 1.5.0+</b> - Data processing and analysis<br/>
    • <b>ReportLab 3.6.0+</b> - PDF report generation<br/>
    • <b>TkinterDnD2</b> - Drag-and-drop file support for GUI<br/>
    • <b>PyYAML 6.0+</b> - Configuration file management
    """
    elements.append(Paragraph(libraries, body_style))
    
    elements.append(Paragraph("Workflow", heading2_style))
    workflow = """
    <b>Analysis Workflow (7 Steps):</b><br/><br/>
    
    1. <b>Ethical Authorization</b> - Verify investigator authorization and compliance<br/>
    2. <b>Evidence Hash Calculation</b> - Generate SHA-256 and MD5 checksums<br/>
    3. <b>Chain of Custody Initialization</b> - Create forensic audit trail<br/>
    4. <b>PCAP File Loading</b> - Read and validate packet capture file<br/>
    5. <b>Protocol Analysis</b> - Extract and categorize network protocols<br/>
    6. <b>Statistics Generation</b> - Create charts and analyze patterns<br/>
    7. <b>Report Generation</b> - Produce comprehensive forensic reports
    """
    elements.append(Paragraph(workflow, body_style))
    
    elements.append(PageBreak())
    
    # ============ 6. EVIDENCE HANDLING (CLO3) ============
    elements.append(Paragraph("6. Evidence Handling (CLO3)", heading1_style))
    
    elements.append(Paragraph("Dataset Info", heading2_style))
    elements.append(Paragraph("""
    <b>Evidence Type:</b> Network Packet Capture Files (.pcap, .pcapng)<br/>
    <b>Sample Dataset:</b> [Describe your test PCAP file - fill in]<br/>
    <b>Source:</b> [e.g., Wireshark sample captures, custom network simulation]<br/>
    <b>Size:</b> [File size - fill in after testing]
    """, body_style))
    
    elements.append(Paragraph("Hashing Results", heading2_style))
    hash_example = """
    The tool automatically generates cryptographic hashes for evidence integrity:<br/><br/>
    
    <b>SHA-256:</b> [Hash will be generated automatically by tool]<br/>
    <b>MD5:</b> [Hash will be generated automatically by tool]<br/><br/>
    
    Hash verification is performed before and after analysis to ensure evidence integrity 
    is maintained throughout the investigation process.
    """
    elements.append(Paragraph(hash_example, body_style))
    
    elements.append(Paragraph("Chain of Custody Form", heading2_style))
    elements.append(Paragraph("""
    <b>Refer to template provided in tool output</b><br/><br/>
    
    The tool automatically generates a comprehensive Chain of Custody (CoC) form including:<br/>
    • Case Information (Case ID, Analyst, Date)<br/>
    • Evidence Details (Type, Name, Size, Hashes)<br/>
    • Storage & Integrity Information<br/>
    • Hash Verification (Before/After Analysis)<br/>
    • Detailed Handling Log<br/>
    • Certification Signatures<br/><br/>
    
    [Include screenshot of generated CoC form from your analysis]
    """, body_style))
    
    elements.append(Paragraph("Ethical/Legal Considerations", heading2_style))
    elements.append(Paragraph("""
    The tool implements ethical compliance checks requiring:<br/>
    • Proper authorization before analysis<br/>
    • Analyst identification and accountability<br/>
    • Complete audit trail of all evidence handling<br/>
    • Integrity verification to prevent tampering<br/>
    • Privacy considerations for sensitive data<br/>
    • Documentation suitable for legal proceedings
    """, body_style))
    
    elements.append(PageBreak())
    
    # ============ 7. IMPLEMENTATION ============
    elements.append(Paragraph("7. Implementation", heading1_style))
    
    elements.append(Paragraph("Screenshot of Tool", heading2_style))
    elements.append(Paragraph("""
    [Insert screenshot of your GUI here - use simple_gui_interface_*.png from artifacts]<br/><br/>
    
    The graphical interface provides:<br/>
    • Drag-and-drop file selection<br/>
    • Case information input fields<br/>
    • Real-time progress tracking<br/>
    • Color-coded status messages<br/>
    • Professional, user-friendly design
    """, body_style))
    
    elements.append(Paragraph("Code Explanation", heading2_style))
    code_explanation = """
    <b>Key Components:</b><br/><br/>
    
    <b>1. Evidence Handler (evidence_handler.py)</b><br/>
    Implements cryptographic hashing using hashlib library. Calculates SHA-256 and MD5 
    checksums for evidence integrity verification.<br/><br/>
    
    <b>2. Packet Analyzer (packet_capture.py)</b><br/>
    Uses Scapy's rdpcap() function to read PCAP files. Iterates through packets extracting 
    layer information (IP, TCP, UDP, etc.).<br/><br/>
    
    <b>3. Suspicious Activity Detector (protocol_analyzer.py)</b><br/>
    Implements detection algorithms for:<br/>
    • Port scanning: Tracks unique destination ports per source IP<br/>
    • SYN floods: Monitors SYN packet rates without corresponding ACK responses<br/><br/>
    
    <b>4. Report Generator (report_generator.py)</b><br/>
    Uses ReportLab to create comprehensive PDF reports with tables, charts, and formatted text. 
    Integrates all analysis results into a single professional document.<br/><br/>
    
    <b>5. GUI Interface (gui_interface.py)</b><br/>
    TkinterDnD2-based interface with drag-and-drop support. Uses threading to prevent UI 
    blocking during analysis. Redirects stdout to display real-time progress.
    """
    elements.append(Paragraph(code_explanation, body_style))
    
    elements.append(PageBreak())
    
    # ============ 8. CASE SCENARIO SIMULATION ============
    elements.append(Paragraph("8. Case Scenario Simulation", heading1_style))
    
    elements.append(Paragraph("Dataset", heading2_style))
    elements.append(Paragraph("""
    [Describe the PCAP file you analyzed - fill in with your actual test case]<br/><br/>
    
    Example: "Downloaded sample network capture from Wireshark website containing HTTP 
    traffic, DNS queries, and TCP connections. File size: X MB, Packets: Y"
    """, body_style))
    
    elements.append(Paragraph("Steps Performed", heading2_style))
    steps = """
    1. Launched GUI interface using <b>python gui_interface.py</b><br/>
    2. Dragged sample PCAP file onto drop zone<br/>
    3. Entered analyst information and case details<br/>
    4. Clicked "Start Analysis" button<br/>
    5. Monitored real-time progress through 7 analysis steps<br/>
    6. Reviewed generated reports in reports/CASE-ID/ directory<br/>
    7. Verified evidence integrity through hash comparison<br/>
    8. Examined Chain of Custody documentation<br/>
    9. Analyzed suspicious activity findings<br/>
    10. Reviewed complete IP address inventory
    """
    elements.append(Paragraph(steps, body_style))
    
    elements.append(Paragraph("Output + Screenshots", heading2_style))
    elements.append(Paragraph("""
    <b>Generated Files:</b><br/>
    • report_CASE-ID.pdf - Comprehensive forensic report<br/>
    • report_CASE-ID.html - Web-viewable version<br/>
    • report_CASE-ID.json - Raw data export<br/>
    • protocol_distribution.png - Protocol chart<br/>
    • top_ips.png - IP statistics chart<br/>
    • top_ports.png - Port usage chart<br/>
    • evidence_hash.json - Hash verification record<br/><br/>
    
    [Include screenshots of:<br/>
    1. GUI with file loaded<br/>
    2. Progress window during analysis<br/>
    3. Completion dialog<br/>
    4. Sample pages from generated PDF report]
    """, body_style))
    
    elements.append(PageBreak())
    
    # ============ 9. RESULTS & ANALYSIS ============
    elements.append(Paragraph("9. Results & Analysis", heading1_style))
    elements.append(Paragraph("Interpret Forensic Findings", heading2_style))
    
    findings = """
    <b>Example Analysis Results:</b><br/><br/>
    
    <b>Network Overview:</b><br/>
    • Total Packets Analyzed: [Fill in from your test]<br/>
    • Unique Source IPs: [Number]<br/>
    • Unique Destination IPs: [Number]<br/>
    • Time Span: [Duration]<br/><br/>
    
    <b>Protocol Distribution:</b><br/>
    • TCP: [X%] - [Count] packets<br/>
    • UDP: [Y%] - [Count] packets<br/>
    • HTTP: [Z%] - [Count] packets<br/>
    • DNS: [W%] - [Count] packets<br/><br/>
    
    <b>Suspicious Activity Detected:</b><br/>
    [If any port scans or SYN floods detected, describe them here]<br/>
    Example: "Port scanning activity detected from IP X.X.X.X targeting 50+ unique ports, 
    classified as HIGH severity. Possible reconnaissance activity."<br/><br/>
    
    <b>Communication Patterns:</b><br/>
    • Most Active Source IP: [IP address] - [packet count]<br/>
    • Most Contacted Destination: [IP address] - [packet count]<br/>
    • Most Used Port: [port number] - [protocol]<br/><br/>
    
    <b>Evidence Integrity:</b><br/>
    ✓ Hash verification successful - Evidence integrity maintained<br/>
    ✓ Complete chain of custody documented<br/>
    ✓ Ethical compliance verified
    """
    elements.append(Paragraph(findings, body_style))
    
    elements.append(PageBreak())
    
    # ============ 10. DISCUSSION ============
    elements.append(Paragraph("10. Discussion", heading1_style))
    
    elements.append(Paragraph("Strengths", heading2_style))
    strengths = """
    • <b>Comprehensive Forensic Documentation:</b> Automated chain of custody and evidence integrity tracking<br/>
    • <b>User-Friendly Interface:</b> Drag-and-drop support and real-time progress monitoring<br/>
    • <b>Automated Detection:</b> Suspicious activity identification without manual analysis<br/>
    • <b>Professional Reporting:</b> Court-ready PDF reports with all required documentation<br/>
    • <b>Complete IP Tracking:</b> Detailed inventory of all source and destination addresses<br/>
    • <b>Modular Architecture:</b> Easy to maintain and extend functionality<br/>
    • <b>Multi-Format Output:</b> HTML, PDF, and JSON for different use cases
    """
    elements.append(Paragraph(strengths, body_style))
    
    elements.append(Paragraph("Limitations", heading2_style))
    limitations = """
    • <b>Post-Capture Only:</b> Does not support live packet capture (relies on existing PCAP files)<br/>
    • <b>Limited Protocol Support:</b> Focuses on common protocols (TCP, UDP, HTTP, DNS)<br/>
    • <b>Scalability:</b> Very large PCAP files (>1GB) may require significant processing time<br/>
    • <b>Windows libpcap Warning:</b> Live capture not available on Windows (not a concern for forensic analysis)<br/>
    • <b>Advanced Analysis:</b> Does not perform deep packet inspection or payload analysis
    """
    elements.append(Paragraph(limitations, body_style))
    
    elements.append(Paragraph("Improvements", heading2_style))
    improvements = """
    • Add support for additional protocols (HTTPS, SMTP, FTP)<br/>
    • Implement machine learning for anomaly detection<br/>
    • Add geolocation mapping for IP addresses<br/>
    • Support for larger datasets through chunked processing<br/>
    • Integration with threat intelligence databases<br/>
    • Export to additional formats (CSV, Excel)<br/>
    • Add timeline visualization features<br/>
    • Implement packet payload search functionality
    """
    elements.append(Paragraph(improvements, body_style))
    
    elements.append(PageBreak())
    
    # ============ 11. CONCLUSION ============
    elements.append(Paragraph("11. Conclusion", heading1_style))
    conclusion = """
    This project successfully developed a comprehensive Network Traffic Analyzer tool that addresses 
    the critical need for automated forensic analysis of network packet captures. The tool effectively 
    combines technical capabilities with forensic best practices, providing investigators with an 
    efficient, reliable, and legally sound solution for network forensic investigations.<br/><br/>
    
    The implementation demonstrates proficiency in Python programming, network protocol analysis, 
    cybersecurity principles, and forensic documentation standards. Key achievements include:<br/><br/>
    
    • Automated evidence integrity verification using cryptographic hashing<br/>
    • Comprehensive chain of custody documentation meeting legal standards<br/>
    • Intelligent suspicious activity detection algorithms<br/>
    • User-friendly interface accessible to both technical and non-technical investigators<br/>
    • Professional, court-ready report generation<br/><br/>
    
    The tool has been validated through testing with real-world network captures, demonstrating its 
    effectiveness in identifying suspicious activities, tracking IP communications, and maintaining 
    proper forensic documentation throughout the investigation process.<br/><br/>
    
    Future enhancements could expand protocol support, integrate threat intelligence, and add advanced 
    visualization features, further increasing the tool's utility in modern digital forensic investigations.
    """
    elements.append(Paragraph(conclusion, body_style))
    
    elements.append(PageBreak())
    
    # ============ 12. REFERENCES ============
    elements.append(Paragraph("12. References (APA/IEEE)", heading1_style))
    references = """
    [Add your references here in APA or IEEE format. Examples:]<br/><br/>
    
    Scapy Project. (2024). Scapy: Packet manipulation library for Python. 
    Retrieved from https://scapy.net/<br/><br/>
    
    Wireshark Foundation. (2024). Wireshark: Network protocol analyzer. 
    Retrieved from https://www.wireshark.org/<br/><br/>
    
    Casey, E. (2011). <i>Digital evidence and computer crime: Forensic science, computers, 
    and the internet</i> (3rd ed.). Academic Press.<br/><br/>
    
    [Add more references as needed for libraries, forensic standards, etc.]
    """
    elements.append(Paragraph(references, body_style))
    
    elements.append(PageBreak())
    
    # ============ 13. APPENDICES ============
    elements.append(Paragraph("13. Appendices", heading1_style))
    
    elements.append(Paragraph("Full Code", heading2_style))
    elements.append(Paragraph("""
    [Include links or references to your GitHub repository or code files]<br/><br/>
    
    GitHub Repository: [Your repository URL]<br/><br/>
    
    Key Files:<br/>
    • network_analyzer.py - Main analysis orchestration<br/>
    • evidence_handler.py - Hash calculation and verification<br/>
    • chain_of_custody.py - CoC documentation<br/>
    • packet_capture.py - Packet reading and parsing<br/>
    • protocol_analyzer.py - Protocol analysis and suspicious activity detection<br/>
    • statistics.py - Statistical analysis and visualizations<br/>
    • report_generator.py - Multi-format report generation<br/>
    • gui_interface.py - Graphical user interface<br/><br/>
    
    [Note: Include code snippets or full files as appendices]
    """, body_style))
    
    elements.append(Paragraph("Extra Screenshots", heading2_style))
    elements.append(Paragraph("""
    [Include additional screenshots showing:]<br/>
    • Different pages of the generated PDF report<br/>
    • Protocol distribution chart<br/>
    • IP statistics visualization<br/>
    • Chain of Custody form<br/>
    • Suspicious activity detection results<br/>
    • GUI in different states (loading, progress, completion)
    """, body_style))
    
    # Footer
    elements.append(Spacer(1, 1*inch))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'],
                                 fontSize=9, textColor=colors.grey,
                                 alignment=TA_CENTER)
    elements.append(Paragraph("--- End of Project Documentation ---", footer_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y')}", footer_style))
    
    # Build PDF
    doc.build(elements)
    print(f"✅ Project documentation template generated: {output_file}")
    return output_file


if __name__ == "__main__":
    print("=" * 70)
    print("PROJECT DOCUMENTATION GENERATOR")
    print("Network Traffic Analyzer - ITT593 Template")
    print("=" * 70)
    print()
    
    output = generate_project_documentation()
    
    print()
    print("=" * 70)
    print("INSTRUCTIONS:")
    print("1. Open the generated PDF file")
    print("2. Fill in sections marked with [Fill in] or [Your content here]")
    print("3. Add screenshots from your actual analysis")
    print("4. Complete the References section")
    print("5. Review and customize content as needed")
    print("=" * 70)
