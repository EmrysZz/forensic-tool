# Testing Datasets and Procedure

This document outlines the specific datasets used for testing the Forensic Tool's detection capabilities and instructions on how to run these tests.

## 📁 Datasets

We utilize real-world attack captures from the [StopDDoS](https://github.com/StopDDoS/packet-captures) repository to validate our anomaly detection algorithms.

### 1. TCP Reflection SYN/ACK Attack
- **File**: `tests/datasets/amp.TCP.reflection.SYNACK.pcap`
- **Source**: [GitHub Link](https://github.com/StopDDoS/packet-captures/blob/main/amp.TCP.reflection.SYNACK.pcap)
- **Description**: This capture contains a TCP reflection attack where the victim receives a flood of SYN-ACK packets (responses to spoofed SYN packets sent to reflectors).
- **Test Objective**: Verify detection of high packet volumes, distributed attack patterns, and potential SYN flood indicators (though technically SYN-ACK floods differ from direct SYN floods).

### 2. UDP DNS ANY Amplification
- **File**: `tests/datasets/amp.UDP.DNSANY.pcap`
- **Source**: [GitHub Link](https://github.com/StopDDoS/packet-captures/blob/main/amp.UDP.DNSANY.pcap)
- **Description**: Contains DNS amplification traffic using `ANY` queries over UDP. This often results in large responses appearing as a UDP flood.
- **Test Objective**: Verify detection of UDP floods, high traffic volume, and DNS-related anomalies.

### 3. DNS RRSIG Fragmented
- **File**: `tests/datasets/amp.dns.RRSIG.fragmented.pcap`
- **Source**: [GitHub Link](https://github.com/StopDDoS/packet-captures/blob/main/amp.dns.RRSIG.fragmented.pcap)
- **Description**: Features fragmented DNS packets involving RRSIG records. Fragmentation is often used to evade detection or in amplification attacks.
- **Test Objective**: Verify the tool's ability to parse and analyze fragmented DNS traffic and detect associated anomalies.

## 🧪 Running Tests

A dedicated test script has been created to analyze these specific datasets.

### Prerequisites
- Ensure the datasets are downloaded to `tests/datasets/`.
- Ensure all project dependencies are installed (`pip install -r requirements.txt`).

### Execution
Run the specific dataset test suite:

```bash
python tests/test_specific_datasets.py
```

### Expected Output
The test script runs the `NetworkAnalyzer` on each pcap and asserts that:
1. The file loads successfully.
2. Packets are parsed.
3. Relevant suspicious activity is detected (e.g., "UDP Flood", "DDoS Indicators").

Example usage output:
```text
Testing tests/datasets/amp.TCP.reflection.SYNACK.pcap...
[*] Loading PCAP file...
[*] Starting protocol analysis...
[+] Analysis complete
TCP Stats: 7674 connections
...
OK
```
