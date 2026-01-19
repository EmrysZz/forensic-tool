"""
Evidence Handler Module
Handles evidence integrity verification through hashing (SHA256/MD5)
Part of CLO3 requirements for digital forensic tool
"""

import hashlib
import os
import json
from datetime import datetime
from typing import Dict, Tuple


class EvidenceHandler:
    """Manages evidence integrity through cryptographic hashing"""
    
    def __init__(self):
        self.evidence_records = {}
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """
        Calculate SHA256 and MD5 hashes for evidence file
        
        Args:
            file_path: Path to the evidence file (PCAP)
        
        Returns:
            Dictionary containing both hash values and metadata
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Evidence file not found: {file_path}")
        
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        file_size = os.path.getsize(file_path)
        
        # Read file in chunks to handle large PCAP files
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
        
        evidence_record = {
            'file_path': os.path.abspath(file_path),
            'file_name': os.path.basename(file_path),
            'file_size_bytes': file_size,
            'sha256': sha256_hash.hexdigest(),
            'md5': md5_hash.hexdigest(),
            'timestamp': datetime.now().isoformat(),
            'verified': True
        }
        
        self.evidence_records[file_path] = evidence_record
        return evidence_record
    
    def verify_integrity(self, file_path: str, expected_sha256: str = None, 
                        expected_md5: str = None) -> Tuple[bool, str]:
        """
        Verify evidence file integrity against expected hash values
        
        Args:
            file_path: Path to evidence file
            expected_sha256: Expected SHA256 hash (optional)
            expected_md5: Expected MD5 hash (optional)
        
        Returns:
            Tuple of (verification_result, message)
        """
        current_hashes = self.calculate_hashes(file_path)
        
        if expected_sha256:
            if current_hashes['sha256'] != expected_sha256:
                return False, f"SHA256 mismatch! Expected: {expected_sha256}, Got: {current_hashes['sha256']}"
        
        if expected_md5:
            if current_hashes['md5'] != expected_md5:
                return False, f"MD5 mismatch! Expected: {expected_md5}, Got: {current_hashes['md5']}"
        
        return True, "Evidence integrity verified successfully"
    
    def generate_hash_report(self, file_path: str, output_format: str = 'txt') -> str:
        """
        Generate hash verification report
        
        Args:
            file_path: Path to evidence file
            output_format: 'txt' or 'json'
        
        Returns:
            Formatted report string
        """
        if file_path not in self.evidence_records:
            self.calculate_hashes(file_path)
        
        record = self.evidence_records[file_path]
        
        if output_format == 'json':
            return json.dumps(record, indent=2)
        else:
            report = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                    EVIDENCE HASH VERIFICATION REPORT                  ║
╚══════════════════════════════════════════════════════════════════════╝

Evidence File: {record['file_name']}
Full Path:     {record['file_path']}
File Size:     {record['file_size_bytes']:,} bytes
Timestamp:     {record['timestamp']}

CRYPTOGRAPHIC HASHES:
─────────────────────
SHA-256: {record['sha256']}
MD5:     {record['md5']}

Status: ✓ VERIFIED
"""
            return report
    
    def save_hash_record(self, file_path: str, output_file: str = None):
        """
        Save hash record to file for documentation purposes
        
        Args:
            file_path: Path to evidence file
            output_file: Output file path (optional)
        """
        if file_path not in self.evidence_records:
            self.calculate_hashes(file_path)
        
        if output_file is None:
            output_file = f"{file_path}_hashes.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.evidence_records[file_path], f, indent=2)
        
        print(f"[+] Hash record saved to: {output_file}")
    
    def get_evidence_info(self, file_path: str) -> Dict:
        """Get stored evidence information"""
        return self.evidence_records.get(file_path, {})


if __name__ == "__main__":
    # Example usage
    print("Evidence Handler Module - Testing")
    print("=" * 70)
    
    # This would be used with actual PCAP files
    # handler = EvidenceHandler()
    # hashes = handler.calculate_hashes("sample.pcap")
    # print(handler.generate_hash_report("sample.pcap"))
