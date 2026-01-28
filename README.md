# 🔍 Network Traffic Analyzer

**Digital Forensic Tool for Network Traffic Analysis**

A comprehensive Python-based forensic tool for analyzing network traffic captures (PCAP files). This tool implements industry-standard forensic practices including evidence hashing, chain-of-custody documentation, and ethical handling procedures.

## ⚡ Features

### Core Functionality
- ✅ **PCAP File Analysis** - Load and analyze network capture files
- ✅ **Protocol Analysis** - Deep inspection of TCP, UDP, HTTP, DNS, and other protocols
- ✅ **Comprehensive Anomaly Detection** - Advanced threat detection including:
  - **DDoS Attacks**: SYN floods, UDP floods, ICMP floods, volumetric attacks, distributed attacks
  - **Network Reconnaissance**: Port scanning, network probing
  - **Malicious File Transfers**: FTP, SMB, HTTP downloads, suspicious file extensions
  - **Traffic Anomalies**: High-volume sources, abnormal patterns
  - 📖 **[View Full Detection Capabilities](docs/detection_capabilities.md)**
- ✅ **Statistical Analysis** - Traffic volume, protocol distribution, top talkers
- ✅ **Visualizations** - Charts and graphs using matplotlib

### CLO3 Forensic Requirements
- ✅ **Evidence Hashing** - SHA-256 and MD5 hash calculation and verification
- ✅ **Chain of Custody** - Complete documentation with JSON and PDF export
- ✅ **Ethical Handling** - Authorization tracking and compliance verification

### Output Formats
- 📊 **HTML Reports** - Interactive reports with embedded visualizations
- 📄 **PDF Reports** - Professional forensic documentation
- 📋 **JSON Exports** - Machine-readable analysis results
- 📈 **Charts** - Protocol distribution, top IPs, port usage

### User Interfaces
- 🖥️ **GUI Interface** - User-friendly graphical interface
- ⌨️ **CLI Interface** - Command-line for automation and scripting

## 🖼️ GUI Interface

The tool includes a **simple, clean graphical interface** with full drag-and-drop support:

**Key Features:**
- 🎯 **Simple Design** - Clean, light theme that's easy to use
- 📂 **Full Drag & Drop** - Drag PCAP files directly onto the interface
- 📊 **Real-Time Progress** - Progress bar with live console output
- ✅ **Ready to Use** - All dependencies included

### How to Launch
```bash
# Launch the GUI (tkinterdnd2 now included in requirements)
python gui_interface.py
```

**Quick Workflow:**
1. **Drag & drop** or browse for PCAP file  
2. **Fill in** analyst name (required) and optional case details
3. **Click** "Start Analysis"
4. **Monitor** progress and view results

### Analysis Results & Reports

![Forensic Analysis Reports](/C:/Users/amiru/.gemini/antigravity/brain/eae7d51a-4482-4e9a-bbae-3e7e9bc8a2ec/analysis_results_charts_1768229799470.png)

**Generated Visualizations:**
- Protocol distribution charts
- IP address analysis
- Port usage statistics
- Suspicious activity alerts
- Evidence integrity verification
- Complete chain of custody documentation

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Windows, Linux, or macOS

### Quick Start

1. **Clone or Download** this repository

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Run Analysis**
```bash
# Using CLI
python network_analyzer.py -f sample.pcap -a "Your Name" --authorized-by "Supervisor"

# Using GUI
python gui_interface.py
```

For detailed installation instructions, see [docs/installation_guide.md](docs/installation_guide.md)

## 🚀 Quick Usage Examples

### Command Line Interface
```bash
# Basic analysis
python network_analyzer.py -f capture.pcap -a "Analyst Name"

# Full forensic analysis
python network_analyzer.py -f capture.pcap -a "John Doe" -c "CASE-2026-001" \
    --authorized-by "IT Manager" --description "Investigating network anomaly"
```

### GUI Interface
```bash
python gui_interface.py
```

### Python API
```python
from network_analyzer import NetworkAnalyzer

analyzer = NetworkAnalyzer()
analyzer.run_analysis(
    pcap_file="sample.pcap",
    analyst_name="Forensic Analyst",
    authorized_by="Security Manager",
    case_description="Network intrusion investigation"
)
```

## 📊 Expected Outputs

The tool generates comprehensive forensic reports including:

1. **List of Source and Destination IPs** - Complete inventory of communicating hosts
2. **Protocol Usage Summary** - Distribution of TCP, UDP, HTTP, DNS, etc.
3. **Suspicious Traffic Report** - Port scans, SYN floods, anomalies
4. **Timeline of Network Events** - Chronological activity analysis
5. **Traffic Statistics Charts** - Visual representations of patterns
6. **Hash Verification Results** - SHA-256 and MD5 integrity checks
7. **Chain of Custody Documentation** - Complete evidence handling trail

### Generated Files Structure
```
reports/CASE-ID/
├── report_CASE-ID.html          # Main HTML report
├── report_CASE-ID.pdf           # PDF summary
├── report_CASE-ID.json          # JSON data export
├── CoC_CASE-ID.pdf              # Chain of Custody
├── CoC_CASE-ID.json             # CoC JSON
├── evidence_hash.json           # Evidence hashes
├── ethical_compliance.json      # Ethical documentation
├── protocol_distribution.png    # Protocol pie chart
├── top_ips.png                  # Top IP addresses
└── top_ports.png                # Port usage
```
## 🧪 Testing & Datasets

We use specific real-world attack datasets to validate the tool's detection capabilities.

- **Datasets Used**:
  - `amp.TCP.reflection.SYNACK.pcap`: TCP Reflection/Amplification
  - `amp.UDP.DNSANY.pcap`: DNS ANY Query Amplification
  - `amp.dns.RRSIG.fragmented.pcap`: Fragmented DNS Traffic

To run the validation tests:
```bash
# Run dataset validation tests
python tests/test_specific_datasets.py
```

📖 **[View Full Testing Documentation](docs/datasets_and_testing.md)** - Details on datasets and expected results.

## 📚 Documentation

Comprehensive documentation available in the `docs/` directory:

- 📖 **[User Manual](docs/user_manual.md)** - Complete usage guide
- 🔧 **[Installation Guide](docs/installation_guide.md)** - Step-by-step setup
- 🚨 **[Detection Capabilities](docs/detection_capabilities.md)** - All 13 threat detection types
- 💡 **[Examples](docs/examples.md)** - Usage examples and walkthroughs
- 🖥️ **[Enhanced GUI Guide](docs/enhanced_gui_guide.md)** - GUI features
- 📋 **[API Reference](docs/api_reference.md)** - Technical documentation
- **[Examples](docs/examples.md)** - Usage examples and tutorials

## 🔬 Project Structure

```
ForensicTool/
├── network_analyzer.py       # Main application
├── gui_interface.py          # GUI interface
├── evidence_handler.py       # Evidence hashing (CLO3)
├── chain_of_custody.py       # CoC documentation (CLO3)
├── ethical_handler.py        # Ethical handling (CLO3)
├── packet_capture.py         # PCAP loading (Scapy)
├── protocol_analyzer.py      # Protocol analysis (Scapy)
├── statistics.py             # Statistics (pandas, matplotlib)
├── report_generator.py       # Report generation
├── requirements.txt          # Python dependencies
├── config.yaml               # Configuration
├── docs/                     # Documentation
│   ├── user_manual.md
│   ├── installation_guide.md
│   ├── api_reference.md
│   └── examples.md
├── tests/                    # Unit tests
└── examples/                 # Sample files
```

## 🛠️ Technologies Used

- **Scapy** - Packet manipulation and analysis
- **PyShark** - Alternative packet parser
- **Pandas** - Data analysis and processing
- **Matplotlib** - Visualization and charts
- **ReportLab** - PDF report generation
- **Tkinter** - GUI interface (built-in with Python)
- **TkinterDnD2** - Drag-and-drop support (optional)

## 🎓 Academic Requirements

This tool fulfills the ITT593 Digital Forensics project requirements:

- ✅ Python-based digital forensic tool
- ✅ Addresses network traffic analysis challenge
- ✅ Uses 2+ relevant Python libraries (Scapy, PyShark, Matplotlib, Pandas)
- ✅ Evidence hashing (SHA-256/MD5) - CLO3
- ✅ Chain-of-custody documentation - CLO3
- ✅ Ethical handling procedures - CLO3
- ✅ Clear and actionable forensic insights
- ✅ Multiple output formats
- ✅ Comprehensive documentation

## 👨‍💻 Author

Digital Forensics Student - ITT593 Project

## 📝 License

This project is created for educational purposes as part of the ITT593 Digital Forensics course.

## 🤝 Contributing

This is an academic project. For improvements or suggestions, please refer to the course guidelines.

## 📧 Support

For questions or issues, please refer to:
- The comprehensive [User Manual](docs/user_manual.md)
- The [Examples](docs/examples.md) documentation
- Course instructor or teaching assistants

---

**⚖️ Legal Notice**: This tool is designed for authorized forensic investigations only. Always obtain proper authorization before analyzing network traffic. Respect privacy rights and follow all applicable laws and regulations.
