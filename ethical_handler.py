"""
Ethical Handler Module
Ensures ethical handling of forensic evidence and data privacy
Part of CLO3 requirements for digital forensic tool
"""

from datetime import datetime
from typing import List, Dict
import json


class EthicalHandler:
    """Manages ethical considerations for forensic analysis"""
    
    ETHICAL_GUIDELINES = [
        "Obtain proper authorization before analyzing network traffic",
        "Respect privacy rights of individuals in captured data",
        "Only access and analyze data necessary for investigation",
        "Maintain confidentiality of sensitive information",
        "Document all actions for transparency and accountability",
        "Follow legal requirements and organizational policies",
        "Avoid unauthorized disclosure of findings",
        "Ensure secure storage and handling of evidence"
    ]
    
    def __init__(self):
        self.consent_record = {
            'authorization_obtained': False,
            'authorized_by': None,
            'authorization_date': None,
            'case_description': None,
            'ethical_checklist': {}
        }
    
    def record_authorization(self, authorized_by: str, case_description: str,
                            authorization_ref: str = None) -> None:
        """
        Record authorization to analyze evidence
        
        Args:
            authorized_by: Name/title of authorizing party
            case_description: Description of investigation
            authorization_ref: Reference number for authorization
        """
        self.consent_record.update({
            'authorization_obtained': True,
            'authorized_by': authorized_by,
            'authorization_date': datetime.now().isoformat(),
            'authorization_ref': authorization_ref or "N/A",
            'case_description': case_description
        })
        
        print(f"[+] Authorization recorded: {authorized_by}")
        print(f"[+] Case: {case_description}")
    
    def check_authorization(self) -> bool:
        """Check if proper authorization has been obtained"""
        return self.consent_record['authorization_obtained']
    
    def complete_ethical_checklist(self, responses: Dict[str, bool] = None) -> Dict:
        """
        Complete ethical handling checklist
        
        Args:
            responses: Dictionary of guideline responses (optional, defaults to all True)
        
        Returns:
            Completed checklist
        """
        checklist = {}
        
        for i, guideline in enumerate(self.ETHICAL_GUIDELINES, 1):
            key = f"item_{i}"
            if responses and key in responses:
                checklist[guideline] = responses[key]
            else:
                checklist[guideline] = True  # Default to compliant
        
        self.consent_record['ethical_checklist'] = checklist
        self.consent_record['checklist_completed_date'] = datetime.now().isoformat()
        
        return checklist
    
    def verify_ethical_compliance(self) -> tuple[bool, List[str]]:
        """
        Verify that all ethical requirements are met
        
        Returns:
            Tuple of (compliance_status, list_of_issues)
        """
        issues = []
        
        # Check authorization
        if not self.consent_record['authorization_obtained']:
            issues.append("⚠ No authorization recorded for this analysis")
        
        # Check ethical checklist
        if not self.consent_record['ethical_checklist']:
            issues.append("⚠ Ethical checklist not completed")
        else:
            for guideline, compliant in self.consent_record['ethical_checklist'].items():
                if not compliant:
                    issues.append(f"⚠ Non-compliance: {guideline}")
        
        is_compliant = len(issues) == 0
        return is_compliant, issues
    
    def generate_ethical_report(self) -> str:
        """
        Generate ethical compliance report
        
        Returns:
            Formatted report string
        """
        is_compliant, issues = self.verify_ethical_compliance()
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════╗
║              ETHICAL HANDLING AND COMPLIANCE REPORT                   ║
╚══════════════════════════════════════════════════════════════════════╝

AUTHORIZATION INFORMATION:
─────────────────────────
Status:           {'✓ AUTHORIZED' if self.consent_record['authorization_obtained'] else '✗ NOT AUTHORIZED'}
Authorized By:    {self.consent_record.get('authorized_by', 'N/A')}
Authorization Ref: {self.consent_record.get('authorization_ref', 'N/A')}
Date:             {self.consent_record.get('authorization_date', 'N/A')}
Case Description: {self.consent_record.get('case_description', 'N/A')}

ETHICAL GUIDELINES CHECKLIST:
─────────────────────────────
"""
        
        if self.consent_record['ethical_checklist']:
            for guideline, compliant in self.consent_record['ethical_checklist'].items():
                status = '✓' if compliant else '✗'
                report += f"{status} {guideline}\n"
        else:
            report += "Checklist not yet completed\n"
        
        report += f"\n{'=' * 70}\n"
        report += f"COMPLIANCE STATUS: {'✓ COMPLIANT' if is_compliant else '✗ NON-COMPLIANT'}\n"
        
        if issues:
            report += "\nISSUES IDENTIFIED:\n"
            for issue in issues:
                report += f"  {issue}\n"
        
        return report
    
    def save_ethical_record(self, output_file: str = None) -> str:
        """
        Save ethical compliance record to JSON file
        
        Args:
            output_file: Output file path
        
        Returns:
            Path to saved file
        """
        if output_file is None:
            output_file = f"ethical_record_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.consent_record, f, indent=2)
        
        print(f"[+] Ethical compliance record saved to: {output_file}")
        return output_file
    
    def get_privacy_guidelines(self) -> List[str]:
        """Get list of privacy and ethical guidelines"""
        return self.ETHICAL_GUIDELINES.copy()


if __name__ == "__main__":
    # Example usage
    print("Ethical Handler Module - Testing")
    print("=" * 70)
    
    # Example workflow
    # handler = EthicalHandler()
    # handler.record_authorization("IT Security Manager", "Investigating network anomaly", "AUTH-2026-001")
    # handler.complete_ethical_checklist()
    # print(handler.generate_ethical_report())
