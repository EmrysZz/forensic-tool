# User Manual

## Network Traffic Analyzer - Digital Forensic Tool

Complete guide for using the Network Traffic Analyzer for forensic investigations.

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [CLI Usage](#cli-usage)
4. [GUI Usage](#gui-usage)
5. [Understanding Outputs](#understanding-outputs)
6. [Forensic Procedures](#forensic-procedures)
7. [Best Practices](#best-practices)

## Introduction

The Network Traffic Analyzer is a forensic tool designed to analyze network traffic captures (PCAP files) while maintaining proper evidence handling procedures including hashing, chain-of-custody, and ethical compliance.

### Key Capabilities
- Analyze TCP, UDP, HTTP, DNS traffic
- **Comprehensive Threat Detection** - 13 detection types across 4 categories:
  - DDoS attacks (SYN, UDP, ICMP floods, volumetric, distributed)
  - Network reconnaissance (port scanning)
  - Malicious file transfers (FTP, SMB, HTTP, suspicious extensions)
  - Traffic anomalies (high-volume sources)
  - 📖 **[View Full Detection Capabilities](detection_capabilities.md)**
- Generate statistical reports and visualizations
- Maintain evidence integrity with cryptographic hashing
- Document chain-of-custody
- Export findings in multiple formats

## Getting Started

### Prerequisites
- Installed Network Traffic Analyzer (see [Installation Guide](installation_guide.md))
- PCAP file to analyze
- Authorization to conduct the analysis

### Quick Start Workflow
1. Obtain proper authorization
2. Collect PCAP evidence file
3. Run analysis (CLI or GUI)
4. Review generated reports
5. Document findings

## CLI Usage

### Command Syntax
```bash
python network_analyzer.py [OPTIONS]
```

### Required Arguments
- `-f, --file PATH` - Path to PCAP file
- `-a, --analyst NAME` - Analyst name

### Optional Arguments
- `-c, --case-id ID` - Case identifier (auto-generated if not provided)
- `--authorized-by NAME` - Who authorized the analysis
- `--description TEXT` - Case description
- `--gui` - Launch GUI interface instead

### Examples

#### Basic Analysis
```bash
python network_analyzer.py -f capture.pcap -a "John Doe"
```

#### Full Forensic Analysis
```bash
python network_analyzer.py \
    -f evidence.pcap \
    -a "Jane Smith" \
    -c "CASE-2026-0042" \
    --authorized-by "IT Security Manager" \
    --description "Investigating suspicious network activity on 2026-01-12"
```

#### Using Auto-Generated Case ID
```bash
python network_analyzer.py -f traffic.pcap -a "Analyst Name" --authorized-by "Supervisor"
```

### Output Location
All reports are saved to `reports/CASE-ID/` directory.

## GUI Usage

### Launching the GUI
```bash
python gui_interface.py
```

Or from the main application:
```bash
python network_analyzer.py --gui
```

### GUI Workflow

#### 1. Select Evidence File
- Click **"📁 Browse PCAP File"**
- Navigate to your PCAP file
- Select the file

#### 2. Enter Case Information
Fill in the required fields:
- **Analyst Name** (required)
- **Case ID** (optional - auto-generated if empty)
- **Authorized By** (recommended for forensic best practices)
- **Description** (optional but recommended)

#### 3. Start Analysis
- Click **"▶ Start Forensic Analysis"**
- Confirm the action
- Monitor progress in the output window

#### 4. View Results
After completion:
- Check the status bar for completion message
- Navigate to `reports/CASE-ID/` folder
- Open the HTML report in a web browser

## Understanding Outputs

### Generated Files

Each analysis creates a comprehensive report package:

```
reports/CASE-ID/
├── report_CASE-ID.html          # Interactive HTML report
├── report_CASE-ID.pdf           # PDF summary report
├── report_CASE-ID.json          # Machine-readable data
├── CoC_CASE-ID.pdf              # Chain of Custody document
├── CoC_CASE-ID.json             # CoC in JSON format
├── evidence_hash.json           # Evidence integrity hashes
├── ethical_compliance.json      # Ethical handling record
├── protocol_distribution.png    # Protocol pie chart
├── top_ips.png                  # Top IP addresses chart
└── top_ports.png                # Port usage chart
```

### Report Sections

#### 1. Case Information
- Case ID and analyst details
- Evidence file information
- Timestamps

#### 2. Evidence Integrity
- **SHA-256 Hash** - Primary integrity verification
- **MD5 Hash** - Secondary verification
- File size and timestamp

#### 3. Executive Summary
High-level overview of findings including:
- Number of unique IPs
- Suspicious activity summary
- Key observations

#### 4. Traffic Statistics
- Protocol distribution (TCP, UDP, HTTP, DNS, etc.)
- Unique source and destination IPs
- Traffic volume metrics

#### 5. IP Communication Analysis
- **Top Source IPs** - Most active sending hosts
- **Top Destination IPs** - Most contacted hosts
- **Conversations** - Communication pairs

#### 6. Protocol-Specific Analysis

**DNS Activity:**
- Total queries and responses
- Top queried domains
- Recent DNS lookups

**HTTP Traffic:**
- HTTP methods used (GET, POST, etc.)
- Requested hosts
- Request timeline

**TCP Connections:**
- Connection count
- Top destination ports
- Connection states (SYN, ACK, FIN)

#### 7. Suspicious Activity

The tool detects **13 types of suspicious activities** across multiple threat categories:

**DDoS Attacks:**
- **SYN Floods** - Incomplete TCP handshakes, excessive SYN packets
- **UDP Floods** - High-volume UDP traffic from single/multiple sources
- **ICMP Floods** - Excessive ping requests (ping floods)
- **Volumetric Attacks** - High packet rates (500+ packets/sec)
- **Distributed DDoS** - Multiple sources targeting single victim

**Network Reconnaissance:**
- **Port Scanning** - Systematic port probing, sequential access patterns

**Malicious File Transfers:**
- **Large Data Transfers** - Potential data exfiltration (50KB+ volumes)
- **Large TCP Transfers** - Bulk file transfers (100KB+ per flow)
- **FTP Activity** - File Transfer Protocol usage
- **SMB/CIFS Activity** - Network file sharing
- **HTTP Downloads** - File downloads with suspicious content types
- **Suspicious File Extensions** - Executables, scripts, malware indicators

**Traffic Anomalies:**
- **High Volume Sources** - IPs generating 3%+ of total traffic

For each detection, the report includes:
- Source/destination IP addresses
- Packet counts and data volumes
- **Severity levels** (CRITICAL/HIGH/MEDIUM)
- Attack type classification
- Detailed indicators

📖 **[Complete Detection Documentation](detection_capabilities.md)** - Detailed thresholds, indicators, and methodology

#### 8. Visualizations
- Protocol distribution pie chart
- Top IPs bar charts
- Port usage graphs

#### 9. Chain of Custody
Timeline of evidence handling:
- Who accessed the evidence
- What actions were performed
- When each action occurred

## Forensic Procedures

### Evidence Handling Workflow

#### 1. Authorization
Always obtain proper authorization before analysis:
```bash
--authorized-by "Security Manager"
--description "Detailed case description"
```

#### 2. Evidence Acquisition
- Obtain PCAP file through approved methods
- Do not modify original evidence
- Create working copies if needed

#### 3. Hash Calculation
The tool automatically:
- Calculates SHA-256 and MD5 hashes
- Records file metadata
- Saves hash record to evidence_hash.json

#### 4. Chain of Custody
Automatically documented:
- Evidence acquisition
- Hash calculation
- Analysis initiation
- Report generation

#### 5. Analysis
The tool performs:
- Protocol parsing
- Anomaly detection
- Statistical analysis
- Pattern recognition

#### 6. Reporting
Multiple formats generated:
- HTML for interactive viewing
- PDF for official documentation
- JSON for data integration

#### 7. Review and Validation
- Verify hash integrity
- Review chain of custody
- Validate findings
- Document conclusions

### Ethical Compliance

The tool enforces ethical practices:

✅ **Authorization Verification** - Ensures proper authorization  
✅ **Privacy Considerations** - Respects data privacy  
✅ **Documentation** - Maintains complete audit trail  
✅ **Transparency** - Clear documentation of all actions  

## Best Practices

### Before Analysis

1. **Obtain Authorization**
   - Get written approval
   - Document authorization source
   - Record case details

2. **Verify Evidence Integrity**
   - Check file is not corrupted
   - Note original hash if available

3. **Prepare Environment**
   - Ensure sufficient disk space
   - Use appropriate permissions
   - Activate virtual environment

### During Analysis

1. **Use Descriptive Case IDs**
   - Include date: `CASE-2026-01-12-001`
   - Reference incident: `BREACH-2026-NETWORK-01`

2. **Provide Complete Information**
   - Full analyst name
   - Detailed descriptions
   - Proper authorization

3. **Monitor Progress**
   - Check for errors
   - Verify completion
   - Review console output

### After Analysis

1. **Review Reports Immediately**
   - Check for anomalies
   - Verify expected findings
   - Note unexpected results

2. **Secure Evidence and Reports**
   - Store in appropriate location
   - Restrict access
   - Backup important findings

3. **Document Additional Findings**
   - Add manual observations
   - Include context
   - Reference external sources

## Advanced Usage

### Analyzing Large PCAP Files

For files > 1 GB:
1. Ensure sufficient RAM
2. Close unnecessary applications
3. Monitor system resources
4. Allow extended processing time

### Filtering Before Analysis

Use Wireshark to pre-filter if needed:
```bash
tshark -r large.pcap -Y "tcp.port == 80" -w filtered.pcap
```

### Batch Processing

Create a script for multiple files:
```bash
#!/bin/bash
for file in *.pcap; do
    python network_analyzer.py -f "$file" -a "Analyst" --authorized-by "Manager"
done
```

### Custom Analysis

Modify `config.yaml` for custom thresholds:
```yaml
detection:
  port_scan_threshold: 50  # Increase if needed
  syn_flood_threshold: 200
```

## Troubleshooting

### Analysis Fails to Start
- Verify PCAP file exists and is readable
- Check file is valid PCAP format
- Ensure sufficient permissions

### Incomplete Reports
- Check disk space
- Verify all dependencies installed
- Review console for errors

### Charts Not Generated
- Ensure matplotlib installed
- Check output directory permissions
- Verify GUI backend available

### Hash Mismatch
- Original file may be modified
- Re-obtain evidence file
- Document discrepancy

## Keyboard Shortcuts (GUI)

- No specific shortcuts currently implemented
- Use mouse to navigate interface

## Command Reference

### All CLI Options
```
-f, --file PATH          PCAP file to analyze (required)
-a, --analyst NAME       Analyst name (required)
-c, --case-id ID         Case identifier (optional)
--authorized-by NAME     Authorization source (optional)
--description TEXT       Case description (optional)
--gui                    Launch GUI mode (optional)
```

## Tips and Tricks

1. **Always provide authorization** for compliance
2. **Use descriptive case IDs** for organization
3. **Review HTML reports** for best visibility
4. **Export JSON** for integration with other tools
5. **Keep chain of custody** complete and accurate
6. **Document everything** - more is better
7. **Verify hashes** before and after analysis

## Getting Help

- Review [Installation Guide](installation_guide.md)
- Check [Examples](examples.md)
- See [API Reference](api_reference.md)
- **Review [Detection Capabilities](detection_capabilities.md)** - Complete threat detection documentation
- Consult course materials

---

**Remember**: Always operate within legal and ethical boundaries. Only analyze authorized network traffic.
