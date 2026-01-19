# Usage Examples

## Network Traffic Analyzer - Practical Examples and Tutorials

This guide provides practical examples and common use cases for the Network Traffic Analyzer tool.

## Table of Contents
1. [Basic Examples](#basic-examples)
2. [Common Scenarios](#common-scenarios)
3. [Advanced Usage](#advanced-usage)
4. [Case Studies](#case-studies)

---

## Basic Examples

### Example 1: Simple PCAP Analysis

**Scenario**: Analyze a basic network capture file

```bash
python network_analyzer.py -f capture.pcap -a "Analyst Name"
```

**What happens:**
1. Tool loads the PCAP file
2. Calculates SHA-256 and MD5 hashes
3. Analyzes all protocols
4. Generates reports in `reports/CASE-TIMESTAMP/`

**Expected Outputs:**
- HTML report with interactive charts
- PDF summary document
- JSON data export
- Protocol distribution chart
- Top IPs visualization

---

### Example 2: Full Forensic Investigation

**Scenario**: Proper forensic analysis with complete documentation

```bash
python network_analyzer.py \
    -f evidence_file.pcap \
    -a "Detective Jane Smith" \
    -c "CASE-2026-SEC-042" \
    --authorized-by "Chief Security Officer" \
    --description "Investigation of data exfiltration incident on January 12, 2026"
```

**What happens:**
1. Records authorization information
2. Completes ethical compliance checklist
3. Full hash verification
4. Comprehensive chain-of-custody documentation
5. Detailed analysis with anomaly detection
6. Professional forensic reports

---

### Example 3: Using the GUI

**Scenario**: User-friendly analysis for non-technical users

```bash
python gui_interface.py
```

**Steps:**
1. Click "Browse PCAP File"
2. Select your file
3. Enter analyst name
4. (Optional) Fill in case information
5. Click "Start Forensic Analysis"
6. Monitor progress window
7. Review generated reports

---

## Common Scenarios

### Scenario 1: Investigating Port Scanning Activity

**Context**: Security team detected potential port scanning

```bash
python network_analyzer.py \
    -f port_scan_capture.pcap \
    -a "Security Analyst" \
    --authorized-by "Security Manager" \
    --description "Investigating suspected port scan from external IP"
```

**What to look for in reports:**
- Check "Suspicious Activity" section
- Review "Port Scanning Activity Detected" table
- Identify source IPs with high port scan counts
- Check severity levels (HIGH/MEDIUM)

**Example Output:**
```
⚠️  SUSPICIOUS ACTIVITY DETECTED:
  - Port Scans: 2 source(s)
    • 203.0.113.45: 127 ports (HIGH)
    • 198.51.100.33: 34 ports (MEDIUM)
```

**Recommended Actions:**
1. Block identified IPs
2. Review firewall logs
3. Check for successful connections
4. Document findings in incident report

---

### Scenario 2: Analyzing HTTP Traffic

**Context**: Investigating web traffic to identify visited websites

```bash
python network_analyzer.py \
    -f web_traffic.pcap \
    -a "Investigator" \
    --description "Analyzing web browsing history"
```

**Analysis Steps:**
1. Open HTML report
2. Navigate to "HTTP Activity" section
3. Review:
   - HTTP methods used (GET, POST)
   - Top requested hosts
   - Request timeline

**Example Findings:**
```
HTTP Activity:
  Total Requests: 234
  Methods:
    GET: 200
    POST: 34
  Top Hosts:
    www.example.com: 45 requests
    api.service.com: 23 requests
```

---

### Scenario 3: DNS Analysis for C2 Detection

**Context**: Looking for command-and-control communication

```bash
python network_analyzer.py \
    -f suspicious_traffic.pcap \
    -a "Malware Analyst" \
    --description "Analyzing potential C2 communication"
```

**What to examine:**
- DNS queries to unusual domains
- High frequency DNS requests
- Domains with suspicious patterns (DGA)
- DNS tunneling indicators

**Red Flags:**
- Many failed DNS queries
- Random-looking domain names
- Unusual TLD usage
- High volume from single host

---

### Scenario 4: Bandwidth Usage Investigation

**Context**: Identify sources of high network usage

**Analysis Focus:**
1. **Protocol Distribution** - Which protocols use most bandwidth?
2. **Top Source IPs** - Which hosts generate most traffic?
3. **Top Destination IPs** - Where is traffic going?

**Example Interpretation:**
```
Protocol Distribution:
  TCP: 1,234 packets (65%)  → Normal
  UDP: 456 packets (24%)    → Normal
  ICMP: 200 packets (11%)   → Potentially suspicious

Top Traffic Sources:
  192.168.1.100: 45% of traffic → INVESTIGATE
  192.168.1.50: 12% of traffic  → Normal
```

**Action Items:**
- Further investigate 192.168.1.100
- Check for data exfiltration
- Review user activity on that host

---

## Advanced Usage

### Custom Analysis with Python API

```python
from packet_capture import PacketCapture
from protocol_analyzer import ProtocolAnalyzer

# Load PCAP
capture = PacketCapture()
capture.load_pcap("traffic.pcap")
packets = capture.get_packets()

# Custom filtering
dns_packets = [p for p in packets if p.haslayer('DNS')]
print(f"Found {len(dns_packets)} DNS packets")

# Analyze specific protocol
analyzer = ProtocolAnalyzer(packets)
dns_results = analyzer.analyze_dns()

for query in dns_results['recent_queries']:
    print(f"Queried: {query['domain']} from {query.get('source_ip', 'unknown')}")
```

---

### Batch Processing Multiple Files

```bash
#!/bin/bash
# Process all PCAP files in a directory

for pcap_file in /path/to/pcaps/*.pcap; do
    echo "Processing $pcap_file"
    python network_analyzer.py \
        -f "$pcap_file" \
        -a "Batch Processor" \
        --authorized-by "Security Team" \
        --description "Batch analysis of captured traffic"
done
```

---

### Filtering Large PCAP Files

Use Wireshark's tshark to pre-filter:

```bash
# Extract only HTTP traffic
tshark -r large.pcap -Y "http" -w http_only.pcap

# Extract traffic to/from specific IP
tshark -r large.pcap -Y "ip.addr == 192.168.1.100" -w filtered.pcap

# Extract specific time range
tshark -r large.pcap -Y "frame.time >= \"2026-01-12 10:00:00\" and frame.time <= \"2026-01-12 12:00:00\"" -w timerange.pcap
```

Then analyze filtered file:
```bash
python network_analyzer.py -f filtered.pcap -a "Analyst"
```

---

## Case Studies

### Case Study 1: Data Breach Investigation

**Background:**
Company suspects data exfiltration via unauthorized file transfer.

**Investigation Steps:**

1. **Capture Traffic**
```bash
# Assuming traffic already captured to breach.pcap
```

2. **Run Analysis**
```bash
python network_analyzer.py \
    -f breach.pcap \
    -a "Lead Investigator" \
    -c "BREACH-2026-001" \
    --authorized-by "Legal Department" \
    --description "Data breach investigation - unauthorized data transfer suspected"
```

3. **Review Findings**
- Check Top Destination IPs for external addresses
- Review HTTP/HTTPS traffic volume
- Identify unusual data transfers
- Check for POST requests to unknown hosts

4. **Key Findings**
```
Suspicious Activity:
  - High volume traffic: 192.168.1.75 (45% of total)
  - Top destination: 203.0.113.89 (suspicious external IP)
  - 127 HTTP POST requests to unknown endpoint
  - Data transfer: ~2.3 GB
```

5. **Documentation**
- Generated reports include full chain-of-custody
- Evidence hashes preserved
- All actions logged
- Ready for legal proceedings

---

### Case Study 2: Insider Threat Detection

**Background:**
HR suspects employee may be exfiltrating intellectual property.

**Approach:**

1. **Authorized Collection**
```bash
# With proper legal authorization
python network_analyzer.py \
    -f employee_traffic.pcap \
    -a "HR Investigator" \
    -c "HR-2026-INSIDER-03" \
    --authorized-by "Chief HR Officer" \
    --description "Authorized investigation of suspected IP theft by employee ID: EMP12345"
```

2. **Focus Areas**
- DNS queries to file sharing sites
- Large outbound transfers
- Off-hours activity
- Encrypted traffic patterns

3. **Findings**
- Multiple connections to cloud storage
- Large file transfers (evidence in packet sizes)
- Activity during non-business hours
- Use of VPN or proxy (encrypted traffic)

---

## Scripting Examples

### Automated Daily Analysis

```python
#!/usr/bin/env python3
"""
Daily automated network analysis
"""
import os
from datetime import datetime
from network_analyzer import NetworkAnalyzer

# Configuration
PCAP_DIR = "/var/captures/daily/"
ANALYST = "Automated System"
AUTHORIZED_BY = "Security Policy"

# Get today's capture
today = datetime.now().strftime("%Y-%m-%d")
pcap_file = os.path.join(PCAP_DIR, f"capture_{today}.pcap")

if os.path.exists(pcap_file):
    analyzer = NetworkAnalyzer()
    analyzer.run_analysis(
        pcap_file=pcap_file,
        analyst_name=ANALYST,
        authorized_by=AUTHORIZED_BY,
        case_description=f"Daily traffic analysis for {today}"
    )
    print(f"Analysis complete for {today}")
else:
    print(f"No capture found for {today}")
```

---

## Tips and Best Practices

### 1. Always Verify Evidence Integrity

Before analysis:
```python
from evidence_handler import EvidenceHandler

handler = EvidenceHandler()
original_hash = "abc123..."  # From evidence log

hashes = handler.calculate_hashes("evidence.pcap")
if hashes['sha256'] == original_hash:
    print("✓ Integrity verified")
else:
    print("✗ HASH MISMATCH - Evidence may be compromised")
```

### 2. Use Descriptive Case IDs

Good examples:
- `INCIDENT-2026-01-12-BREACH`
- `SEC-2026-Q1-001`
- `FORENSIC-MALWARE-20260112`

Poor examples:
- `case1`
- `test`
- `analysis`

### 3. Document Everything

Include detailed descriptions:
```bash
--description "Investigation initiated following IDS alert #12345 on 2026-01-12 09:23 UTC. Suspected port scan from external IP targeting web servers. Duration of attack: approximately 15 minutes. Incident reported by SOC analyst. Legal approval obtained via ticket #SEC-2026-042."
```

---

## Troubleshooting Examples

### Example: PCAP File Won't Load

```python
from packet_capture import PacketCapture

capture = PacketCapture()
if not capture.load_pcap("suspicious.pcap"):
    # Check file
    import os
    if not os.path.exists("suspicious.pcap"):
        print("File not found")
    else:
        print(f"File size: {os.path.getsize('suspicious.pcap')} bytes")
        # Try alternative method or check file corruption
```

---

## Additional Resources

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Scapy Tutorial](https://scapy.readthedocs.io/)
- Sample PCAP files: [tcpreplay.com](https://tcpreplay.appneta.com/)

---

**Remember**: Always obtain proper authorization before analyzing network traffic. Respect privacy and legal requirements.
