import os
import time
import re
from config import Config

class HTMLReportGenerator:
    def __init__(self):
        self.css_styles = Config.HTML_STYLES
    
    def _escape_html(self, text):
        """Escape HTML special characters."""
        html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&apos;",
            ">": "&gt;",
            "<": "&lt;",
        }
        return "".join(html_escape_table.get(c, c) for c in text)
    
    def _get_section_class(self, section_title):
        section_classes = {
            "File Information": "file-info",
            "Basic Information": "file-info",
            "File Hashes": "hash-info",
            "PE Header Information": "pe-info",
            "PE Sections": "pe-info",
            "Imported DLLs and Functions": "pe-info",
            "Exported Functions": "pe-info",
            "Extracted Strings": "strings-info",
            "VirusTotal Analysis": "vt-info",
            "Known Names": "vt-info",
            "Malicious Detections": "vt-info",
            "Dynamic Analysis": "dynamic-info",
            "Detected Signatures": "dynamic-info",
            "Processes": "dynamic-info",
            "Network Activity": "dynamic-info",
            "Extracted URLs": "dynamic-info",
            "MITRE ATT&CK Techniques": "dynamic-info",
            "Dropped Files": "dynamic-info",
            "Interesting Behaviors": "dynamic-info"
        }
        return section_classes.get(section_title, "")
    
    def _parse_sections(self, text_content):
        """Parse content into sections."""
        # Split content by the section headers
        sections = []
        section_pattern = r"={80}\n(.*?)\n={80}(.*?)(?=\n={80}|\Z)"
        matches = re.finditer(section_pattern, text_content, re.DOTALL)
        
        content_by_section = {}
        for match in matches:
            section_title = match.group(1).strip()
            section_content = match.group(2).strip()
            
            # Only add non-empty sections
            if section_content:
                content_by_section[section_title] = section_content
        
        return content_by_section
    
    def _format_section_content(self, section_title, content):
        """Format section content as HTML."""
        html = f'<div class="section {self._get_section_class(section_title)}">\n'
        html += f'<h2 class="section-header">{section_title}</h2>\n'
        
        # Format content based on section type
        if section_title in ["File Information", "Basic Information", "File Hashes"]:
            processed_keys = set()
            for line in content.split('\n'):
                if not line.strip():
                    continue
                if ':' in line:
                    key, value = line.split(':', 1)
                    key_clean = key.strip()
                    if key_clean in processed_keys:
                        continue
                    processed_keys.add(key_clean)
                    html += f'<div class="key-value"><span class="key">{key_clean}:</span> '
                    html += f'<span class="value">{value.strip()}</span></div>\n'
                else:
                    html += f'<div>{line}</div>\n'
        
        elif section_title == "Imported DLLs and Functions":
            current_dll = None
            seen_functions = set()
            for line in content.split('\n'):
                if not line.strip():
                    continue
                if line.strip().startswith('📚'):
                    if current_dll:
                        html += '</div>\n'  
                        seen_functions = set()  
                    current_dll = line.strip().replace('📚', '').strip()
                    html += f'<div class="dll-name">{current_dll}</div>\n'
                    html += '<div class="function-list">\n'
                elif current_dll and line.strip().startswith('→'):
                    function = line.strip().replace('→', '').strip()
                    if function not in seen_functions:
                        seen_functions.add(function)
                        html += f'<div>{function}</div>\n'
            if current_dll:
                html += '</div>\n' 
        
        elif section_title == "Malicious Detections":
            html += '<div class="warning">\n'
            # Deduplicate detections
            seen_detections = set()
            for line in content.split('\n'):
                if not line.strip():
                    continue
                if line.strip() not in seen_detections:
                    seen_detections.add(line.strip())
                    html += f'<div class="malicious">{line}</div>\n'
            html += '</div>\n'
        
        elif section_title == "Processes" or section_title == "Detected Signatures":
            entries = content.split('\n\n')
            processed_entries = []
            
            for entry in entries:
                if not entry.strip():
                    continue
                    
                entry_key = entry.split('\n')[0] if entry.split('\n') else ""
                if any(entry_key in previous for previous in processed_entries):
                    continue 
                
                processed_entries.append(entry)
                html += '<div class="key-value">\n'
                for line in entry.split('\n'):
                    if not line.strip():
                        continue
                    if ':' in line:
                        key, value = line.split(':', 1)
                        html += f'<div><span class="key">{key.strip()}:</span> '
                        html += f'<span class="value">{value.strip()}</span></div>\n'
                    else:
                        html += f'<div>{line}</div>\n'
                html += '</div>\n<div class="separator"></div>\n'
        
        elif section_title in ["Extracted URLs", "Network Activity"]:
            seen_items = set()
            html += '<ul>\n'
            for line in content.split('\n'):
                if not line.strip():
                    continue
                # Remove bullet points if present
                cleaned_line = re.sub(r'^[•→\-\s]+', '', line.strip())
                if cleaned_line not in seen_items:
                    seen_items.add(cleaned_line)
                    
                    # Make URLs clickable if they look like URLs
                    if section_title == "Extracted URLs" and (cleaned_line.startswith("http://") or cleaned_line.startswith("https://")):
                        html += f'<li><a href="{cleaned_line}" target="_blank">{cleaned_line}</a></li>\n'
                    else:
                        html += f'<li>{cleaned_line}</li>\n'
            html += '</ul>\n'
        
        else:
            html += f'<pre>{self._escape_html(content)}</pre>\n'
        
        html += '</div>\n'
        return html
    
    def generate_from_text(self, text_content, output_file=None):
        if not output_file:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_dir = Config.OUTPUT_FOLDER
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"analysis_report_{timestamp}.html")
        
        html = '<!DOCTYPE html>\n<html>\n<head>\n'
        html += '<meta charset="UTF-8">\n'
        html += '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        html += '<title>Analysis Report</title>\n'
        html += f'<style>\n{self.css_styles}\n</style>\n'
        html += '</head>\n<body>\n'
        

        if "VirusTotal Analysis" in text_content:
            title = "VirusTotal Analysis Report"
        elif "Dynamic Analysis" in text_content:
            title = "Dynamic Analysis Report"
        elif "PE Header" in text_content:
            title = "Static Analysis Report"
        else:
            title = "Malware Analysis Report"
        
        html += f'<h1 class="report-header">{title}</h1>\n'
        html += f'<div class="timestamp">Generated on: {time.strftime("%Y-%m-%d %H:%M:%S")}</div>\n'
        
        # Parse and format content by section
        content_by_section = self._parse_sections(text_content)
        
        if content_by_section:
            for section_title, content in content_by_section.items():
                html += self._format_section_content(section_title, content)
        else:
            # If no sections were found, format the entire content
            html += f'<div class="section">\n<pre>{self._escape_html(text_content)}</pre>\n</div>\n'
        
        html += '</body>\n</html>'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_file 