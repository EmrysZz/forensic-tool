# Suspicious Activity Detection Capabilities

The Network Traffic Analyzer includes comprehensive detection algorithms to identify various types of malicious and suspicious network activities. This document outlines all detection capabilities currently implemented in the tool.

---

## 🚨 DDoS Attack Detection

### 1. **SYN Flood Attacks**
- **Detection Method**: Monitors TCP SYN packets and SYN-ACK responses
- **Threshold**: 25+ SYN packets from a single source IP
- **Indicators**:
  - High volume of SYN packets
  - Incomplete TCP handshakes (high SYN/SYN-ACK ratio)
  - Abnormal connection patterns
- **Severity Levels**:
  - **CRITICAL**: 500+ SYN packets
  - **HIGH**: 100-499 SYN packets
  - **MEDIUM**: 25-99 SYN packets

### 2. **UDP Flood Attacks**
- **Detection Method**: Counts UDP packets from each source IP
- **Threshold**: 50+ UDP packets from a single source
- **Indicators**:
  - Excessive UDP traffic from single or multiple sources
  - High-volume connectionless traffic
- **Severity Levels**:
  - **CRITICAL**: 500+ UDP packets
  - **HIGH**: 150-499 UDP packets
  - **MEDIUM**: 50-149 UDP packets

### 3. **ICMP Flood Attacks (Ping Floods)**
- **Detection Method**: Monitors ICMP request packets
- **Threshold**: 25+ ICMP packets from a single source
- **Indicators**:
  - Excessive ping requests
  - Abnormal ICMP traffic volume
- **Severity Levels**:
  - **CRITICAL**: 250+ ICMP packets
  - **HIGH**: 75-249 ICMP packets
  - **MEDIUM**: 25-74 ICMP packets

### 4. **Volumetric Attacks**
- **Detection Method**: Calculates overall packet rate (packets per second)
- **Threshold**: 500+ packets per second
- **Indicators**:
  - Extremely high packet rates
  - Network bandwidth saturation
  - Short-duration traffic spikes
- **Severity Levels**:
  - **CRITICAL**: 5,000+ packets/sec
  - **HIGH**: 1,000-4,999 packets/sec
  - **MEDIUM**: 500-999 packets/sec

### 5. **Distributed DDoS Attacks**
- **Detection Method**: Analyzes multiple sources targeting single destination
- **Threshold**: 5+ unique source IPs with 200+ total packets to one target
- **Indicators**:
  - Multiple source IPs attacking same target
  - Coordinated attack pattern
  - Geographic distribution of attackers
- **Severity Levels**:
  - **CRITICAL**: 25+ unique attackers
  - **HIGH**: 10-24 unique attackers
  - **MEDIUM**: 5-9 unique attackers

---

## 🔍 Network Reconnaissance Detection

### 6. **Port Scanning**
- **Detection Method**: Tracks unique destination ports contacted by each IP
- **Threshold**: 5+ different ports scanned
- **Indicators**:
  - Systematic port probing
  - Sequential or random port access patterns
  - Failed connection attempts
- **Severity Levels**:
  - **CRITICAL**: 50+ ports scanned
  - **HIGH**: 20-49 ports scanned
  - **MEDIUM**: 5-19 ports scanned

---

## 📊 Traffic Anomaly Detection

### 7. **High Volume IP Addresses**
- **Detection Method**: Calculates each IP's percentage of total traffic
- **Threshold**: 3%+ of total network traffic from single IP
- **Indicators**:
  - Disproportionate traffic volume
  - Potential C2 servers or data exfiltration
  - Abnormal bandwidth usage
- **Severity Levels**:
  - **CRITICAL**: 40%+ of total traffic
  - **HIGH**: 20-39% of total traffic
  - **MEDIUM**: 3-19% of total traffic

---

## 📁 Malicious File Transfer Detection

### 8. **Large Data Transfers**
- **Detection Method**: Tracks total data volume per source IP
- **Threshold**: 50KB+ and 5%+ of total data volume
- **Indicators**:
  - Potential data exfiltration
  - Unusual upload/download volumes
  - Suspicious data movement patterns
- **Severity Levels**:
  - **CRITICAL**: 5MB+ data volume
  - **HIGH**: 500KB-5MB data volume
  - **MEDIUM**: 50KB-500KB data volume

### 9. **Large TCP Transfers**
- **Detection Method**: Monitors individual TCP connection data volumes
- **Threshold**: 100KB+ per TCP flow
- **Indicators**:
  - Large file downloads/uploads
  - Bulk data transfer in single connection
- **Severity Levels**:
  - **HIGH**: 1MB+ per flow
  - **MEDIUM**: 100KB-1MB per flow

### 10. **FTP Activity**
- **Detection Method**: Detects traffic on FTP ports (20, 21)
- **Threshold**: Any FTP connection
- **Indicators**:
  - File Transfer Protocol usage
  - Unencrypted file transfers
  - Potential data movement
- **Severity Level**: **MEDIUM** (all FTP activity)

### 11. **SMB/CIFS File Sharing**
- **Detection Method**: Detects traffic on SMB ports (139, 445)
- **Threshold**: Any SMB connection
- **Indicators**:
  - Network file sharing activity
  - Potential lateral movement
  - Windows file sharing protocols
- **Severity Level**: **MEDIUM** (all SMB activity)

### 12. **HTTP File Downloads**
- **Detection Method**: Analyzes HTTP responses for file attachments
- **Threshold**: HTTP responses with Content-Type: application/* or attachment
- **Indicators**:
  - File downloads via HTTP
  - Executable or binary file transfers
  - Potentially malicious downloads
- **Severity Level**: **MEDIUM** (all HTTP downloads)

### 13. **Suspicious File Extensions**
- **Detection Method**: Scans packet payloads for known malicious file extensions
- **Monitored Extensions**:
  - **HIGH Risk**: `.exe`, `.dll`, `.bat`, `.ps1`, `.key`, `.pem`
  - **MEDIUM Risk**: `.vbs`, `.zip`, `.rar`, `.7z`, `.sql`, `.db`, `.docm`, `.xlsm`, `.jar`, `.apk`
- **Indicators**:
  - Executable files in transit
  - Encrypted archives
  - Macro-enabled documents
  - Mobile applications
  - Private keys or certificates
- **Severity Levels**:
  - **HIGH**: Executables, scripts, private keys
  - **MEDIUM**: Archives, databases, macro documents

---

## 📋 Detection Summary Table

| **Category** | **Attack Type** | **Min Threshold** | **Primary Indicator** |
|--------------|----------------|-------------------|----------------------|
| **DDoS** | SYN Flood | 25 packets | Incomplete handshakes |
| **DDoS** | UDP Flood | 50 packets | High UDP volume |
| **DDoS** | ICMP Flood | 25 packets | Excessive pings |
| **DDoS** | Volumetric | 500 pkt/sec | High packet rate |
| **DDoS** | Distributed | 5 sources, 200 pkts | Multiple attackers |
| **Recon** | Port Scan | 5 ports | Sequential probing |
| **Anomaly** | High Volume IP | 3% of traffic | Disproportionate usage |
| **Transfer** | Large Data | 50KB, 5% volume | Data exfiltration |
| **Transfer** | Large TCP | 100KB per flow | Bulk transfer |
| **Transfer** | FTP | Any activity | FTP protocol |
| **Transfer** | SMB/CIFS | Any activity | File sharing |
| **Transfer** | HTTP Download | Content-Type match | File downloads |
| **Transfer** | Suspicious Files | Extension match | Malicious extensions |

---

## 🎯 How Detection Works

### Analysis Pipeline
1. **Packet Inspection**: All packets are analyzed using Scapy
2. **Pattern Recognition**: Algorithms identify attack signatures
3. **Threshold Evaluation**: Activities exceeding thresholds are flagged
4. **Severity Assessment**: Each detection is assigned a severity level
5. **Report Generation**: Findings are documented in JSON, PDF, and HTML

### Real-Time vs. PCAP Analysis
- **PCAP Files**: Complete analysis of captured traffic
- **Detection Accuracy**: Based on configurable, research-backed thresholds
- **False Positive Reduction**: Multiple indicators required for high-severity alerts

---

## 📊 Output Reporting

Detected suspicious activities are reported in:

### 1. **Executive Summary**
- High-level overview of all detected threats
- Count of each attack type
- Overall security assessment

### 2. **Detailed Reports (JSON/PDF/HTML)**
- Complete details for each detected activity
- Source/destination IP addresses
- Packet counts and data volumes
- Severity classifications
- Attack timestamps

### 3. **Chain of Custody**
- Documented evidence trail
- Analysis methodology
- Forensic integrity verification

---

## 🔧 Customization

Detection thresholds can be adjusted in `protocol_analyzer.py`:
- Modify packet count thresholds
- Adjust percentage-based detection
- Add custom file extensions
- Configure severity levels

---

## 📚 References

Detection algorithms based on industry-standard practices:
- NIST Special Publication 800-94: Guide to Intrusion Detection and Prevention Systems
- SANS Institute DDoS Attack Detection Guidelines
- MITRE ATT&CK Framework

---

## ⚠️ Important Notes

- **Baseline Required**: Effectiveness improves with network baseline understanding
- **False Positives**: Legitimate high-volume applications may trigger alerts
- **Threshold Tuning**: Adjust thresholds based on your network environment
- **Regular Updates**: Keep detection signatures and thresholds current

---

*Last Updated: January 2026*  
*Version: 2.0*
