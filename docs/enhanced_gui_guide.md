# GUI User Guide

## Overview
The GUI provides a simple, clean interface for the Network Traffic Analyzer forensic tool.

## Features
✨ **Clean Design**: Light theme with simple layout
📂 **Drag & Drop**: Full drag-and-drop support for PCAP files
📊 **Progress Tracking**: Real-time progress bar with console output
🎯 **Easy to Use**: Straightforward workflow

## Installation

tkinterdnd2 is included in requirements.txt:
```bash
pip install -r requirements.txt
```

## Usage

### Launch the GUI
```bash
python gui_interface.py
```

### Workflow
1. **Select Evidence File**
   - Drag & drop a PCAP file onto the blue zone, OR
   - Click "Browse" button to select manually

2. **Enter Case Information**
   - **Analyst Name** (Required): Your name
   - **Case ID** (Optional): Auto-generated if not provided
   - **Authorized By**: Person who authorized the investigation
   - **Case Description**: Brief description

3. **Start Analysis**
   - Click the green "Start Analysis" button
   - Confirm the action
   - Monitor real-time progress

4. **View Results**
   - Completion dialog shows case ID and report location
   - Reports saved to `reports/CASE-ID/` directory

## Color Scheme
- **Header**: Blue (#4a90e2)
- **Drop Zone**: Light blue (#e8f4f8)
- **Start Button**: Green (#28a745)
- **Background**: White

## Troubleshooting

### Window appears too small/large
The window auto-sizes to 900x750 and centers on screen. You can resize manually.

### Analysis not starting
Ensure:
- PCAP file is selected
- Analyst name is filled in
- File is a valid .pcap or .pcapng file

### ImportError for tkinterdnd2
Install the dependency:
```bash
pip install tkinterdnd2
```

## Previous Versions
- `gui_interface_original.py` - Original simple GUI
- `gui_interface_enhanced.py` - Dark theme enhanced version
