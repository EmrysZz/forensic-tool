
import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib import colors

def convert_md_to_pdf(input_file, output_file):
    doc = SimpleDocTemplate(output_file, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))
    styles.add(ParagraphStyle(name='CustomCode', 
                              parent=styles['Normal'],
                              fontName='Courier',
                              fontSize=9,
                              leading=12,
                              backColor=colors.lightgrey,
                              spaceBefore=6,
                              spaceAfter=6))
    
    story = []

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    in_code_block = False
    code_block_content = []

    for line in lines:
        line = line.rstrip()
        
        # Code Blocks
        if line.startswith('```'):
            if in_code_block:
                # End of code block
                p = Preformatted('\n'.join(code_block_content), styles['CustomCode'])
                story.append(p)
                story.append(Spacer(1, 12))
                in_code_block = False
                code_block_content = []
            else:
                in_code_block = True
            continue
            
        if in_code_block:
            code_block_content.append(line)
            continue
            
        # Headers
        if line.startswith('# '):
            story.append(Paragraph(line[2:], styles['Title']))
            story.append(Spacer(1, 12))
        elif line.startswith('## '):
            story.append(Paragraph(line[3:], styles['Heading2']))
            story.append(Spacer(1, 12))
        elif line.startswith('### '):
            story.append(Paragraph(line[4:], styles['Heading3']))
            story.append(Spacer(1, 12))
        
        # Lists
        elif line.strip().startswith('- '):
            # Simple bullet point handling
            text = line.strip()[2:]
            # Bold handling for **text**
            text = text.replace('**', '<b>', 1).replace('**', '</b>', 1)
            # Link handling for [text](url) - Simplified
            # Only supports simple replacement, not full regex for now
            story.append(Paragraph(f"• {text}", styles['Normal']))
            story.append(Spacer(1, 6))
            
        # Text
        elif line.strip():
            text = line
            text = text.replace('**', '<b>', 1).replace('**', '</b>', 1)
            story.append(Paragraph(text, styles['Normal']))
            story.append(Spacer(1, 12))

    doc.build(story)
    print(f"Successfully converted {input_file} to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python md_to_pdf.py <input.md> <output.pdf>")
        sys.exit(1)
        
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    
    try:
        convert_md_to_pdf(input_path, output_path)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
