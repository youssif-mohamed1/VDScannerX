import re
import os

class Config:
    # API Configuration
    VIRUSTOTAL_API_KEY = '1f943b55964dc8763921324f04fe0885fa7d212e10502e11320446c2e28278bb'
    
    # File System Configuration
    OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output_pdf')
    
    # String Filters
    FILTERS = {
        "All": None,
        "URLs":      re.compile(rb"https?://[^\s\"']+"),
        "IPs":       re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "Registry":  re.compile(rb"HKEY_[A-Z_\\]+"),
        "Paths":     re.compile(rb"[A-Za-z]:\\[^:*?\"<>|\r\n]+"),
        "DLLs":      re.compile(rb"[a-zA-Z0-9_]+\.(dll|DLL)"),
        "Commands":  re.compile(rb"\b(cmd\.exe|powershell|wmic|whoami|tasklist|netstat|curl|wget)\b", re.IGNORECASE),
    }
    
    # PDF Report Configuration
    PDF_STYLES = {
        'title': {
            'font': 'Helvetica-Bold',
            'size': 24,
            'color': (0.2, 0.3, 0.7),  # Blue
        },
        'section_header': {
            'font': 'Helvetica-Bold',
            'size': 14,
            'color': (0.2, 0.3, 0.7),  # Blue
            'background': (0.95, 0.95, 0.95),  # Light Gray
        },
        'normal_text': {
            'font': 'Helvetica',
            'size': 11,
            'color': (0, 0, 0),  # Black
        },
        'page_number': {
            'font': 'Helvetica',
            'size': 8,
            'color': (0, 0, 0),  # Black
        }
    } 