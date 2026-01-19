"""
Unit Tests for Network Traffic Analyzer
"""

import unittest
import os
import tempfile
from evidence_handler import EvidenceHandler
from chain_of_custody import ChainOfCustody


class TestEvidenceHandler(unittest.TestCase):
    """Test cases for evidence_handler module"""
    
    def setUp(self):
        """Create temporary test file"""
        self.test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        self.test_file.write(b'Test data for hashing')
        self.test_file.close()
        self.handler = EvidenceHandler()
    
    def tearDown(self):
        """Clean up test file"""
        os.unlink(self.test_file.name)
    
    def test_calculate_hashes(self):
        """Test hash calculation"""
        result = self.handler.calculate_hashes(self.test_file.name)
        
        self.assertIn('sha256', result)
        self.assertIn('md5', result)
        self.assertEqual(len(result['sha256']), 64)  # SHA256 is 64 hex characters
        self.assertEqual(len(result['md5']), 32)      # MD5 is 32 hex characters
    
    def test_verify_integrity(self):
        """Test integrity verification"""
        hashes = self.handler.calculate_hashes(self.test_file.name)
        
        # Should pass with correct hash
        result, msg = self.handler.verify_integrity(
            self.test_file.name,
            expected_sha256=hashes['sha256']
        )
        self.assertTrue(result)
        
        # Should fail with incorrect hash
        result, msg = self.handler.verify_integrity(
            self.test_file.name,
            expected_sha256='incorrect_hash'
        )
        self.assertFalse(result)


class TestChainOfCustody(unittest.TestCase):
    """Test cases for chain_of_custody module"""
    
    def setUp(self):
        """Create temporary test file"""
        self.test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        self.test_file.close()
        self.coc = ChainOfCustody(self.test_file.name, "TEST-CASE-001")
    
    def tearDown(self):
        """Clean up"""
        os.unlink(self.test_file.name)
    
    def test_add_entry(self):
        """Test adding CoC entry"""
        self.coc.add_entry("Test Action", "Test Analyst", "A001", "Test notes")
        entries = self.coc.get_all_entries()
        
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['action'], "Test Action")
        self.assertEqual(entries[0]['analyst_name'], "Test Analyst")
    
    def test_generate_report(self):
        """Test report generation"""
        self.coc.add_entry("Action 1", "Analyst 1")
        self.coc.add_entry("Action 2", "Analyst 2")
        
        report = self.coc.generate_report()
        
        self.assertIn("CHAIN OF CUSTODY", report)
        self.assertIn("TEST-CASE-001", report)
        self.assertIn("Action 1", report)
        self.assertIn("Action 2", report)


class TestPacketCapture(unittest.TestCase):
    """Test cases for packet_capture module"""
    
    def test_metadata_structure(self):
        """Test packet capture metadata"""
        from packet_capture import PacketCapture
        
        capture = PacketCapture()
        metadata = capture.get_metadata()
        
        self.assertIsInstance(metadata, dict)


if __name__ == '__main__':
    unittest.main()
