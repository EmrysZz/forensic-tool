"""
Chain of Custody Module
Maintains detailed chain-of-custody documentation for forensic evidence
Part of CLO3 requirements for digital forensic tool
"""

import json
import os
from datetime import datetime
from typing import List, Dict
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer


class ChainOfCustody:
    """Manages chain-of-custody documentation for forensic evidence"""
    
    def __init__(self, evidence_file: str, case_id: str = None):
        """
        Initialize Chain of Custody record
        
        Args:
            evidence_file: Path to evidence file
            case_id: Optional case identifier
        """
        self.evidence_file = os.path.abspath(evidence_file)
        self.case_id = case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.coc_record = {
            'case_id': self.case_id,
            'evidence_file': self.evidence_file,
            'file_name': os.path.basename(evidence_file),
            'created_date': datetime.now().isoformat(),
            'entries': []
        }
    
    def add_entry(self, action: str, analyst_name: str, analyst_id: str = None, 
                  notes: str = "") -> None:
        """
        Add a chain-of-custody entry
        
        Args:
            action: Action performed (e.g., "Acquired", "Analyzed", "Transferred")
            analyst_name: Name of person handling evidence
            analyst_id: Optional analyst identifier
            notes: Additional notes
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'analyst_name': analyst_name,
            'analyst_id': analyst_id or "N/A",
            'notes': notes,
            'entry_number': len(self.coc_record['entries']) + 1
        }
        
        self.coc_record['entries'].append(entry)
        print(f"[+] CoC Entry Added: {action} by {analyst_name}")
    
    def get_all_entries(self) -> List[Dict]:
        """Get all chain-of-custody entries"""
        return self.coc_record['entries']
    
    def save_to_json(self, output_file: str = None) -> str:
        """
        Save chain-of-custody record to JSON file
        
        Args:
            output_file: Output file path (optional)
        
        Returns:
            Path to saved file
        """
        if output_file is None:
            output_file = f"CoC_{self.case_id}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.coc_record, f, indent=2)
        
        print(f"[+] Chain of Custody saved to: {output_file}")
        return output_file
    
    def generate_report(self) -> str:
        """
        Generate formatted text report of chain-of-custody
        
        Returns:
            Formatted CoC report string
        """
        report = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                   CHAIN OF CUSTODY DOCUMENTATION                      ║
╚══════════════════════════════════════════════════════════════════════╝

Case ID:         {self.coc_record['case_id']}
Evidence File:   {self.coc_record['file_name']}
Full Path:       {self.coc_record['evidence_file']}
Created:         {self.coc_record['created_date']}
Total Entries:   {len(self.coc_record['entries'])}

CUSTODY CHAIN ENTRIES:
{'=' * 70}
"""
        
        for entry in self.coc_record['entries']:
            report += f"""
Entry #{entry['entry_number']}
─────────────────────
Timestamp:    {entry['timestamp']}
Action:       {entry['action']}
Analyst:      {entry['analyst_name']} (ID: {entry['analyst_id']})
Notes:        {entry['notes'] or 'None'}
"""
        
        report += f"\n{'=' * 70}\n"
        report += "End of Chain of Custody Documentation\n"
        
        return report
    
    def export_to_pdf(self, output_file: str = None) -> str:
        """
        Export chain-of-custody to PDF report
        
        Args:
            output_file: Output PDF file path
        
        Returns:
            Path to generated PDF
        """
        if output_file is None:
            output_file = f"CoC_{self.case_id}.pdf"
        
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Create style for wrapping text
        wrap_style = ParagraphStyle(
            'WrapStyle',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            wordWrap='CJK'
        )
        
        # Title
        title = Paragraph("<b>CHAIN OF CUSTODY DOCUMENTATION</b>", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 20))
        
        # Case Information
        case_info = [
            ['Case ID:', self.coc_record['case_id']],
            ['Evidence File:', self.coc_record['file_name']],
            ['Full Path:', Paragraph(self.coc_record['evidence_file'], wrap_style)],
            ['Created:', self.coc_record['created_date']],
            ['Total Entries:', str(len(self.coc_record['entries']))]
        ]
        
        case_table = Table(case_info, colWidths=[120, 350])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(case_table)
        elements.append(Spacer(1, 20))
        
        # Chain of Custody Entries
        if self.coc_record['entries']:
            elements.append(Paragraph("<b>Custody Chain Entries:</b>", styles['Heading2']))
            elements.append(Spacer(1, 10))
            
            entry_data = [['#', 'Timestamp', 'Action', 'Analyst', 'Notes']]
            
            for entry in self.coc_record['entries']:
                entry_data.append([
                    str(entry['entry_number']),
                    entry['timestamp'][:19],
                    Paragraph(entry['action'], wrap_style),
                    Paragraph(f"{entry['analyst_name']}\n({entry['analyst_id']})", wrap_style),
                    Paragraph(entry['notes'][:80] if entry['notes'] else 'None', wrap_style)
                ])
            
            entry_table = Table(entry_data, colWidths=[25, 100, 80, 120, 145])
            entry_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('FONTSIZE', (0, 1), (0, -1), 7),  # # column
                ('FONTSIZE', (1, 1), (1, -1), 7),  # Timestamp column
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            elements.append(entry_table)
        
        doc.build(elements)
        print(f"[+] Chain of Custody PDF generated: {output_file}")
        return output_file


if __name__ == "__main__":
    # Example usage
    print("Chain of Custody Module - Testing")
    print("=" * 70)
    
    # Example workflow
    # coc = ChainOfCustody("sample.pcap", "CASE-2026-001")
    # coc.add_entry("Evidence Acquired", "John Doe", "A001", "PCAP file from network tap")
    # coc.add_entry("Hash Calculated", "John Doe", "A001", "SHA256 and MD5 generated")
    # coc.add_entry("Analysis Started", "Jane Smith", "A002", "Network traffic analysis initiated")
    # print(coc.generate_report())
