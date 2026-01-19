# API Reference

## Network Traffic Analyzer - Developer Documentation

This document provides detailed API documentation for developers who want to use or extend the Network Traffic Analyzer tool.

## Module Overview

### Core Modules
1. **evidence_handler** - Evidence integrity and hashing
2. **chain_of_custody** - CoC documentation
3. **ethical_handler** - Ethical compliance
4. **packet_capture** - PCAP file handling
5. **protocol_analyzer** - Deep packet inspection
6. **statistics** - Statistical analysis and visualization
7. **report_generator** - Multi-format reporting
8. **network_analyzer** - Main application
9. **gui_interface** - Graphical interface

---

## evidence_handler.py

### Class: `EvidenceHandler`

Manages evidence integrity through cryptographic hashing (SHA-256, MD5).

#### Methods

##### `calculate_hashes(file_path: str) -> Dict[str, str]`
Calculate SHA-256 and MD5 hashes for evidence file.

**Parameters:**
- `file_path` (str): Path to the evidence file

**Returns:**
- Dict containing hash values and metadata

**Example:**
```python
from evidence_handler import EvidenceHandler

handler = EvidenceHandler()
hashes = handler.calculate_hashes("evidence.pcap")
print(f"SHA-256: {hashes['sha256']}")
print(f"MD5: {hashes['md5']}")
```

##### `verify_integrity(file_path: str, expected_sha256: str = None, expected_md5: str = None) -> Tuple[bool, str]`
Verify file integrity against expected hashes.

**Returns:**
- Tuple of (verification_result, message)

##### `generate_hash_report(file_path: str, output_format: str = 'txt') -> str`
Generate formatted hash verification report.

**Parameters:**
- `output_format`: 'txt' or 'json'

---

## chain_of_custody.py

### Class: `ChainOfCustody`

Maintains chain-of-custody documentation for forensic evidence.

#### Methods

##### `__init__(evidence_file: str, case_id: str = None)`
Initialize CoC record.

##### `add_entry(action: str, analyst_name: str, analyst_id: str = None, notes: str = "")`
Add a chain-of-custody entry.

**Example:**
```python
from chain_of_custody import ChainOfCustody

coc = ChainOfCustody("evidence.pcap", "CASE-2026-001")
coc.add_entry("Evidence Acquired", "John Doe", "A001", "Initial acquisition")
coc.add_entry("Analysis Started", "Jane Smith", "A002")
```

##### `export_to_pdf(output_file: str = None) -> str`
Export chain-of-custody to PDF format.

##### `generate_report() -> str`
Generate formatted text report.

---

## packet_capture.py

### Class: `PacketCapture`

Handles PCAP file loading and basic packet operations using Scapy.

#### Methods

##### `load_pcap(file_path: str) -> bool`
Load PCAP file for analysis.

**Example:**
```python
from packet_capture import PacketCapture

capture = PacketCapture()
if capture.load_pcap("traffic.pcap"):
    print(f"Loaded {capture.get_packet_count()} packets")
    metadata = capture.get_metadata()
```

##### `capture_live(interface: str = None, count: int = 100, timeout: int = 30, filter_str: str = None) -> bool`
Capture live network traffic (optional feature).

##### `filter_packets(filter_func) -> List`
Filter packets using custom function.

**Example:**
```python
# Get only HTTP packets
http_packets = capture.filter_packets(
    lambda pkt: pkt.haslayer('TCP') and pkt['TCP'].dport == 80
)
```

---

## protocol_analyzer.py

### Class: `ProtocolAnalyzer`

Analyzes network protocols and detects anomalies.

#### Methods

##### `__init__(packets: List)`
Initialize analyzer with packet list.

##### `analyze_all() -> Dict`
Perform comprehensive analysis.

**Returns:**
Dictionary containing:
- `protocol_distribution`
- `ip_communications`
- `dns_activity`
- `http_activity`
- `tcp_connections`
- `udp_connections`
- `suspicious_activity`

**Example:**
```python
from protocol_analyzer import ProtocolAnalyzer

analyzer = ProtocolAnalyzer(packets)
results = analyzer.analyze_all()

# Access specific results
protocols = results['protocol_distribution']
dns = results['dns_activity']
suspicious = results['suspicious_activity']
```

##### `analyze_protocols() -> Dict`
Analyze protocol distribution.

##### `analyze_ip_traffic() -> Dict`
Analyze IP traffic patterns.

##### `detect_anomalies() -> Dict`
Detect suspicious patterns (port scans, SYN floods).

---

## statistics.py

### Class: `StatisticsGenerator`

Generates statistics and visualizations using pandas and matplotlib.

#### Methods

##### `__init__(analysis_results: Dict)`
Initialize with analysis results from ProtocolAnalyzer.

##### `generate_all_stats(output_dir: str = "reports") -> Dict`
Generate all statistics and save charts.

**Example:**
```python
from statistics import StatisticsGenerator

stats_gen = StatisticsGenerator(analysis_results)
statistics = stats_gen.generate_all_stats("output/")
charts = stats_gen.get_generated_charts()
```

##### `create_protocol_chart(output_file: str)`
Create protocol distribution pie chart.

##### `create_top_ips_chart(output_file: str)`
Create top IPs bar chart.

---

## report_generator.py

### Class: `ReportGenerator`

Creates comprehensive forensic reports in multiple formats.

#### Methods

##### `__init__(case_id: str = None)`
Initialize report generator.

##### `set_metadata(analyst: str, evidence_file: str, summary: str = "")`
Set report metadata.

##### `add_findings(analysis_results: Dict, statistics: Dict, evidence_hash: Dict, coc_entries: List)`
Add analysis findings to report.

##### `export_json(output_file: str = None) -> str`
Export report as JSON.

##### `export_html(output_file: str = None, chart_files: List[str] = None) -> str`
Export report as HTML with embedded charts.

##### `export_pdf(output_file: str = None) -> str`
Export report as PDF.

**Example:**
```python
from report_generator import ReportGenerator

report = ReportGenerator("CASE-2026-001")
report.set_metadata("Analyst Name", "evidence.pcap", "Summary text")
report.add_findings(analysis_results, statistics, hashes, coc_entries)

html_file = report.export_html()
pdf_file = report.export_pdf()
```

---

## network_analyzer.py

### Class: `NetworkAnalyzer`

Main application class orchestrating all components.

#### Methods

##### `run_analysis(pcap_file: str, analyst_name: str, case_id: str = None, authorized_by: str = None, case_description: str = "")`
Run complete forensic analysis workflow.

**Example:**
```python
from network_analyzer import NetworkAnalyzer

analyzer = NetworkAnalyzer()
analyzer.run_analysis(
    pcap_file="evidence.pcap",
    analyst_name="Forensic Analyst",
    case_id="CASE-2026-001",
    authorized_by="Security Manager",
    case_description="Network intrusion investigation"
)
```

---

## Complete Usage Example

```python
#!/usr/bin/env python3
"""
Complete example of using the Network Traffic Analyzer API
"""

from evidence_handler import EvidenceHandler
from chain_of_custody import ChainOfCustody
from packet_capture import PacketCapture
from protocol_analyzer import ProtocolAnalyzer
from statistics import StatisticsGenerator
from report_generator import ReportGenerator

# Initialize components
evidence = EvidenceHandler()
pcap_file = "evidence.pcap"

# Calculate hashes
hashes = evidence.calculate_hashes(pcap_file)
print(f"SHA-256: {hashes['sha256']}")

# Initialize chain of custody
coc = ChainOfCustody(pcap_file, "CASE-2026-001")
coc.add_entry("Acquired", "Analyst", notes="Initial acquisition")

# Load PCAP
capture = PacketCapture()
capture.load_pcap(pcap_file)
packets = capture.get_packets()

# Analyze protocols
analyzer = ProtocolAnalyzer(packets)
results = analyzer.analyze_all()

# Generate statistics
stats_gen = StatisticsGenerator(results)
stats = stats_gen.generate_all_stats("output/")

# Generate reports
report = ReportGenerator("CASE-2026-001")
report.set_metadata("Analyst Name", pcap_file)
report.add_findings(results, stats, hashes, coc.get_all_entries())
report.export_html()

print("Analysis complete!")
```

---

## Extending the Tool

### Adding Custom Analyzers

Create custom protocol analyzers:

```python
class CustomAnalyzer:
    def __init__(self, packets):
        self.packets = packets
    
    def analyze_custom_protocol(self):
        # Your analysis logic
        results = {}
        for packet in self.packets:
            # Process packet
            pass
        return results
```

### Custom Report Formats

Extend ReportGenerator:

```python
class CustomReportGenerator(ReportGenerator):
    def export_csv(self, output_file):
        # Custom CSV export logic
        pass
```

### Custom Anomaly Detection

Add to ProtocolAnalyzer:

```python
def detect_custom_anomaly(self):
    suspicious = []
    # Your detection logic
    return suspicious
```

---

## Data Structures

### Analysis Results Structure

```python
{
    'protocol_distribution': {
        'TCP': {'count': 1234, 'percentage': 45.2},
        'UDP': {'count': 890, 'percentage': 32.5},
        ...
    },
    'ip_communications': {
        'top_source_ips': {'192.168.1.1': 500, ...},
        'top_destination_ips': {'8.8.8.8': 300, ...},
        'unique_source_ips': 45,
        'unique_destination_ips': 120
    },
    'suspicious_activity': {
        'port_scans': [
            {'source_ip': '10.0.0.1', 'ports_scanned': 100, 'severity': 'HIGH'}
        ],
        'syn_floods': [...]
    }
}
```

---

## Error Handling

All modules include error handling:

```python
try:
    capture.load_pcap("file.pcap")
except FileNotFoundError:
    print("PCAP file not found")
except Exception as e:
    print(f"Error: {e}")
```

---

## Dependencies

- **scapy**: Packet manipulation
- **matplotlib**: Visualization
- **pandas**: Data processing
- **reportlab**: PDF generation
- **pyyaml**: Configuration

---

## Thread Safety

The GUI runs analysis in a separate thread to prevent UI freezing:

```python
import threading

thread = threading.Thread(target=analysis_function)
thread.daemon = True
thread.start()
```

---

## Performance Considerations

- Large PCAP files (>1GB) may require significant RAM
- Chart generation can be time-consuming
- Consider batch processing for multiple files

---

## Testing

Example unit test:

```python
import unittest
from evidence_handler import EvidenceHandler

class TestEvidenceHandler(unittest.TestCase):
    def test_hash_calculation(self):
        handler = EvidenceHandler()
        # Test implementation
```

---

For more examples, see [examples.md](examples.md)
