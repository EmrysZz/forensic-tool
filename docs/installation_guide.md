# Installation Guide

## Network Traffic Analyzer - Digital Forensic Tool

This guide provides step-by-step installation instructions for Windows, Linux, and macOS.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), or macOS 10.15+
- **Python**: 3.8 or higher
- **RAM**: 4 GB minimum (8 GB recommended)
- **Disk Space**: 500 MB for application and dependencies
- **Network**: Internet connection for installing dependencies

### Recommended Requirements
- Python 3.10 or higher
- 8 GB RAM or more
- SSD for faster PCAP file processing

## Installation Steps

### 1. Install Python

#### Windows
1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run the installer and **check "Add Python to PATH"**
3. Verify installation:
```cmd
python --version
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
python3 --version
```

#### macOS
```bash
# Using Homebrew
brew install python@3.10
python3 --version
```

### 2. Download the Tool

Download or clone the Network Traffic Analyzer project to your local machine.

```bash
# If using git
git clone <repository-url>
cd ForensicTool

# Or download and extract ZIP file
```

### 3. Create Virtual Environment (Recommended)

Creating a virtual environment keeps dependencies isolated:

#### Windows
```cmd
python -m venv venv
venv\Scripts\activate
```

#### Linux/macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` in your command prompt when activated.

### 4. Install Dependencies

With the virtual environment activated:

```bash
pip install -r requirements.txt
```

This will install:
- **scapy** (≥2.5.0) - Packet manipulation
- **pyshark** (≥0.6) - Packet parsing (optional, requires Wireshark/tshark)
- **matplotlib** (≥3.5.0) - Visualization
- **pandas** (≥1.5.0) - Data analysis
- **reportlab** (≥3.6.0) - PDF generation
- **pyyaml** (≥6.0) - Configuration

### 5. Verify Installation

Test that all modules can be imported:

```python
python -c "import scapy; import matplotlib; import pandas; import reportlab; print('All dependencies installed successfully!')"
```

### 6. Install Additional Requirements (Optional)

#### For PyShark Support
PyShark requires Wireshark's tshark to be installed:

**Windows:**
- Download and install Wireshark from [wireshark.org](https://www.wireshark.org/)
- Ensure tshark is in your PATH

**Linux:**
```bash
sudo apt install tshark
```

**macOS:**
```bash
brew install wireshark
```

## Platform-Specific Notes

### Windows

1. **Administrator Privileges**: Live packet capture requires administrator rights
2. **Npcap**: Scapy on Windows requires Npcap (installed with Wireshark)
3. **Firewall**: May need to allow Python through Windows Firewall

### Linux

1. **Permissions**: For live capture, run with sudo or add user to appropriate group:
```bash
sudo usermod -a -G wireshark $USER
```

2. **libpcap**: Install if not already present:
```bash
sudo apt install libpcap-dev
```

### macOS

1. **Command Line Tools**: May need Xcode Command Line Tools:
```bash
xcode-select --install
```

2. **Permissions**: Live capture may require sudo

## Troubleshooting

### ImportError: No module named 'scapy'
**Solution**: Ensure virtual environment is activated and run:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### matplotlib display issues
**Solution**: On Linux, install GUI backend:
```bash
sudo apt install python3-tk
```

### Permission denied when capturing
**Solution**: 
- Windows: Run as Administrator
- Linux/macOS: Use sudo or set appropriate permissions

### ReportLab PDF generation fails
**Solution**: Check if reportlab installed correctly:
```bash
pip uninstall reportlab
pip install reportlab==3.6.12
```

## Testing the Installation

### 1. Test CLI Interface
```bash
python network_analyzer.py --help
```

You should see the help menu with all available options.

### 2. Test GUI Interface
```bash
python gui_interface.py
```

The GUI window should open successfully.

### 3. Run with Sample Data
Create a test PCAP file or download a sample:
```bash
python network_analyzer.py -f examples/sample.pcap -a "Test User" --authorized-by "Supervisor"
```

## Updating the Tool

To update dependencies to the latest versions:

```bash
pip install --upgrade -r requirements.txt
```

## Uninstallation

### Remove Virtual Environment
```bash
# Deactivate first
deactivate

# Remove directory
# Windows
rmdir /s venv

# Linux/macOS
rm -rf venv
```

### Remove Dependencies
If installed globally (not recommended):
```bash
pip uninstall -r requirements.txt
```

## Next Steps

After successful installation:

1. Read the [User Manual](user_manual.md) for usage instructions
2. Review [Examples](examples.md) for common scenarios
3. Check [API Reference](api_reference.md) for development

## Getting Help

If you encounter issues:

1. Check this troubleshooting section
2. Verify Python version: `python --version`
3. Check pip version: `pip --version`
4. Review error messages carefully
5. Consult course instructor or TA

## Security Considerations

- Keep Python and all dependencies updated
- Use virtual environments to isolate dependencies
- Only analyze authorized network traffic
- Follow organizational security policies

---

**Installation complete!** You're ready to use the Network Traffic Analyzer tool.
