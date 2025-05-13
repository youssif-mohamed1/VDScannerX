import os
import time
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from config import Config

class PDFReportGenerator:
    def __init__(self, filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        self.filename = filename
        self.c = canvas.Canvas(self.filename, pagesize=A4)
        self.width, self.height = A4
        self.margin = 60  # Increased margin for better readability
        self.content_width = self.width - 2 * self.margin
        self.y = self.height - self.margin
        self.line_height = 16  # Increased line height
        self.section_spacing = 25  # Increased section spacing
        
        # Enhanced color scheme with additional semantic colors
        self.colors = {
            'primary': HexColor('#1a73e8'),     # Google Blue
            'secondary': HexColor('#4285f4'),   # Light Blue
            'accent': HexColor('#fbbc04'),      # Yellow
            'danger': HexColor('#ea4335'),      # Red
            'success': HexColor('#34a853'),     # Green
            'text': HexColor('#202124'),        # Dark Gray
            'subtext': HexColor('#5f6368'),     # Medium Gray
            'background': HexColor('#f8f9fa'),  # Light Gray
            'section_bg': HexColor('#f1f3f4'),  # Section Background
            'highlight': HexColor('#e8f0fe'),   # Highlight Background
            'link': HexColor('#1967d2'),        # Link Color
            'border': HexColor('#dadce0'),      # Border Color
        }
        
        # Set document metadata
        self.c.setTitle("Security Analysis Report")
        self.c.setAuthor("PE File Analyzer")
        self.c.setSubject("Security Analysis")
        
        # Set default font
        self.c.setFont("Helvetica", 11)

    def draw_header(self, title):
        # Draw a modern header with subtle gradient
        self.c.saveState()
        
        # Draw header background
        self.c.setFillColor(self.colors['background'])
        self.c.rect(0, self.height - 150, self.width, 150, fill=1, stroke=0)
        
        # Draw accent line
        self.c.setFillColor(self.colors['primary'])
        self.c.rect(0, self.height - 152, self.width, 4, fill=1, stroke=0)
        
        # Draw title
        self.c.setFillColor(self.colors['primary'])
        self.c.setFont("Helvetica-Bold", 28)
        self.c.drawString(self.margin, self.height - 70, title)
        
        # Draw timestamp and metadata
        self.c.setFillColor(self.colors['subtext'])
        self.c.setFont("Helvetica", 11)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        self.c.drawString(self.margin, self.height - 100, f"Generated on: {timestamp}")
        
        # Draw decorative elements
        self.c.setStrokeColor(self.colors['secondary'])
        self.c.setLineWidth(1)
        self.c.line(self.margin, self.height - 110, self.margin + 200, self.height - 110)
        
        self.c.restoreState()
        self.y = self.height - 170
        self.reset_style()

    def draw_section(self, title, section_type="default"):
        if self.y < self.margin + 100:
            self.new_page()
        
        self.y -= self.section_spacing
        
        # Enhanced section-specific styling
        section_styles = {
            "basic_info": {
                "icon": "ℹ️",
                "color": self.colors['primary'],
                "bg": self.colors['highlight'],
                "accent": self.colors['secondary']
            },
            "malware": {
                "icon": "⚠️",
                "color": self.colors['danger'],
                "bg": HexColor('#ffebee'),
                "accent": HexColor('#ff8a80')
            },
            "pe_info": {
                "icon": "🔍",
                "color": self.colors['secondary'],
                "bg": self.colors['section_bg'],
                "accent": self.colors['primary']
            },
            "strings": {
                "icon": "📝",
                "color": self.colors['success'],
                "bg": HexColor('#f1f8e9'),
                "accent": HexColor('#81c784')
            },
            "hashes": {
                "icon": "🔒",
                "color": HexColor('#6200ee'),  # Deep Purple
                "bg": HexColor('#f3e5f5'),     # Light Purple
                "accent": HexColor('#9c27b0')   # Purple
            },
            "default": {
                "icon": "📋",
                "color": self.colors['primary'],
                "bg": self.colors['section_bg'],
                "accent": self.colors['secondary']
            }
        }
        
        # Get section style based on title or type
        if title == "File Hashes":
            style = section_styles["hashes"]
        else:
            style = section_styles.get(section_type, section_styles["default"])
        
        # Draw modern section header with enhanced styling
        self.c.saveState()
        
        # Draw main background with gradient effect
        bg_height = 50  # Increased height
        for i in range(bg_height):
            alpha = 1 - (i / bg_height) * 0.5  # Gradient from 100% to 50% opacity
            self.c.setFillColor(self._adjust_color_alpha(style['bg'], alpha))
            self.c.rect(
                self.margin - 15,
                self.y - 25 + i,
                self.content_width + 30,
                1,
                fill=1,
                stroke=0
            )
        
        # Draw left accent bar
        self.c.setFillColor(style['accent'])
        self.c.rect(
            self.margin - 15,
            self.y - 25,
            5,
            bg_height,
            fill=1,
            stroke=0
        )
        
        # Draw header content
        self.c.setFillColor(style['color'])
        self.c.setFont("Helvetica-Bold", 18)  # Increased font size
        
        # Draw icon with background circle
        icon_x = self.margin
        icon_y = self.y - 5
        circle_radius = 12
        
        # Draw icon background
        self.c.setFillColor(style['accent'])
        self.c.circle(icon_x + circle_radius, icon_y - circle_radius, circle_radius, fill=1)
        
        # Draw icon
        self.c.setFillColor(HexColor('#ffffff'))  # White color for icon
        self.c.setFont("Helvetica-Bold", 14)
        icon_width = self.c.stringWidth(style['icon'], "Helvetica-Bold", 14)
        self.c.drawString(
            icon_x + circle_radius - icon_width/2,
            icon_y - circle_radius - 5,
            style['icon']
        )
        
        # Draw title
        self.c.setFillColor(style['color'])
        self.c.setFont("Helvetica-Bold", 18)
        self.c.drawString(icon_x + circle_radius*2 + 10, self.y - 5, title)
        
        # Draw decorative elements
        self.c.setStrokeColor(style['accent'])
        self.c.setLineWidth(1)
        
        # Draw accent lines
        line_start = icon_x + circle_radius*2 + 10 + self.c.stringWidth(title, "Helvetica-Bold", 18) + 15
        line_length = 40
        spacing = 8
        
        for i in range(3):
            self.c.line(
                line_start + (i * (line_length + spacing)),
                self.y - 5,
                line_start + (i * (line_length + spacing)) + line_length,
                self.y - 5
            )
        
        # Add subtle texture
        self.c.setStrokeColor(self._adjust_color_alpha(style['accent'], 0.2))
        self.c.setLineWidth(0.5)
        
        pattern_start = self.width - self.margin - 100
        pattern_width = 80
        pattern_height = 30
        
        for i in range(0, pattern_width, 8):
            self.c.line(
                pattern_start + i,
                self.y - pattern_height,
                pattern_start + i + pattern_height,
                self.y
            )
        
        self.c.restoreState()
        self.y -= 60  # Increased spacing after header
        self.reset_style()

    def _adjust_color_alpha(self, color, alpha):
        """Helper method to adjust color opacity"""
        if isinstance(color, str):
            color = HexColor(color)
        r, g, b = color.red, color.green, color.blue
        return colors.Color(r, g, b, alpha)

    def write_line(self, text, indent=0, color=None, style=None):
        if self.y < self.margin + 50:
            self.new_page()
        
        # Enhanced text styling
        styles = {
            'header': {
                'font': 'Helvetica-Bold',
                'size': 12,
                'color': self.colors['primary']
            },
            'key': {
                'font': 'Helvetica-Bold',
                'size': 11,
                'color': self.colors['text']
            },
            'value': {
                'font': 'Helvetica',
                'size': 11,
                'color': color or self.colors['text']
            },
            'warning': {
                'font': 'Helvetica-Bold',
                'size': 11,
                'color': self.colors['danger']
            },
            'success': {
                'font': 'Helvetica',
                'size': 11,
                'color': self.colors['success']
            },
            'code': {
                'font': 'Courier',
                'size': 10,
                'color': self.colors['text']
            }
        }
        
        text_style = styles.get(style, styles['value'])
        
        # Set text style
        self.c.setFont(text_style['font'], text_style['size'])
        self.c.setFillColor(text_style['color'])
        
        # Handle special formatting
        if ':' in text and style != 'code':
            key, value = text.split(':', 1)
            # Draw key in bold
            self.c.setFont('Helvetica-Bold', text_style['size'])
            self.c.drawString(self.margin + indent, self.y, f"{key}:")
            # Draw value
            self.c.setFont(text_style['font'], text_style['size'])
            self.c.drawString(self.margin + indent + self.c.stringWidth(f"{key}: ", 'Helvetica-Bold', text_style['size']),
                            self.y, value)
        else:
            if text.startswith('•'):
                bullet_indent = 15
                self.c.setFont('Helvetica-Bold', text_style['size'])
            elif text.startswith('→'):
                bullet_indent = 20
                self.c.setFont('Courier', text_style['size'])
                text = '→ ' + text[1:].strip()
            elif text.startswith('📚'):
                bullet_indent = 0
                self.c.setFont('Helvetica-Bold', text_style['size'])
            else:
                bullet_indent = 0
            
            self.c.drawString(self.margin + indent + bullet_indent, self.y, text)
        
        self.y -= self.line_height
        self.reset_style()

    def new_page(self):

        self.draw_footer()
        

        self.c.showPage()
        self.y = self.height - self.margin
        

        self.c.saveState()
        

        self.c.setFillColor(self.colors['background'])
        self.c.rect(0, self.height - 50, self.width, 50, fill=1, stroke=0)
        
        self.c.setFillColor(self.colors['primary'])
        self.c.setFont("Helvetica-Bold", 14)
        self.c.drawString(self.margin, self.height - 30, "Security Analysis Report")
        

        self.c.setStrokeColor(self.colors['secondary'])
        self.c.setLineWidth(1)
        self.c.line(0, self.height - 52, self.width, self.height - 52)
        
        self.c.restoreState()
        self.y = self.height - 70
        self.reset_style()

    def draw_footer(self):
        self.c.saveState()
        

        self.c.setFillColor(self.colors['background'])
        self.c.rect(0, 0, self.width, 40, fill=1, stroke=0)
        

        self.c.setStrokeColor(self.colors['secondary'])
        self.c.setLineWidth(1)
        self.c.line(0, 41, self.width, 41)
        

        self.c.setFillColor(self.colors['subtext'])
        self.c.setFont("Helvetica", 9)
        page_num = f"Page {self.c.getPageNumber()}"
        self.c.drawRightString(self.width - self.margin, 15, page_num)
        

        self.c.setFont("Helvetica", 9)
        self.c.drawString(self.margin, 15, "PE File Analyzer")
        
        self.c.restoreState()

    def reset_style(self):
        self.c.setFillColor(self.colors['text'])
        self.c.setFont("Helvetica", 11)

    def generate_from_text(self, text_content):
        """Generate a report from text content with enhanced section formatting"""

        text_content = text_content.replace("Please wait...", "")
        text_content = text_content.replace("Analyzing hash:", "Hash:")
        text_content = text_content.replace("Analyzing file...", "")
        

        if "VirusTotal Analysis" in text_content:
            title = "VirusTotal Analysis Report"
        elif "PE File Analysis" in text_content:
            title = "PE File Static Analysis Report"
        elif "File Information" in text_content:
            title = "File Analysis Report"
        else:
            title = "Security Analysis Report"
            
        self.draw_header(title)
        

        section_configs = {
            "Basic Information": {"type": "basic_info", "style": "key"},
            "Known Names": {"type": "default", "style": "value"},
            "Malicious Detections": {"type": "malware", "style": "warning"},
            "File Information": {"type": "basic_info", "style": "key"},
            "File Hashes": {"type": "hashes", "style": "code"},  # Updated style
            "PE Header Information": {"type": "pe_info", "style": "value"},
            "PE Sections": {"type": "pe_info", "style": "key"},
            "Imported DLLs and Functions": {"type": "pe_info", "style": "code"},
            "Exported Functions": {"type": "pe_info", "style": "code"},
            "Extracted Strings": {"type": "strings", "style": "value"}
        }
        

        content_by_section = self._parse_sections(text_content, list(section_configs.keys()))
        
        for section, content in content_by_section.items():
            config = section_configs.get(section, {"type": "default", "style": "value"})
            self.draw_section(section, config["type"])
            

            if section in ["Malicious Detections", "Imported DLLs and Functions"]:
                count = len([l for l in content.split('\n') if l.strip()])
                self.write_line(f"Total entries: {count}", style='header')
                self.y -= 10
            

            self._format_section_content(content, config["style"])
        
        if not content_by_section:
            self._format_section_content(text_content)
        
        self.draw_footer()
        self.c.save()

    def _parse_sections(self, text_content, known_sections):
        """Parse content into sections with improved handling"""
        content_by_section = {}
        for section in known_sections:
            start_marker = f"{'='*80}\n{section}\n{'='*80}"
            if start_marker in text_content:
                section_start = text_content.find(start_marker) + len(start_marker)
                section_end = len(text_content)
                
                for next_section in known_sections:
                    if next_section != section:
                        next_marker = f"{'='*80}\n{next_section}\n{'='*80}"
                        next_pos = text_content.find(next_marker, section_start)
                        if next_pos > -1 and next_pos < section_end:
                            section_end = next_pos
                
                section_content = text_content[section_start:section_end].strip()
                if section_content:
                    content_by_section[section] = section_content
        
        return content_by_section

    def _format_section_content(self, content, style='value'):
        """Format section content with consistent styling"""
        lines = content.split('\n')
        for line in lines:
            if not line.strip():
                continue
            
            indent = len(line) - len(line.lstrip())
            content = line.strip()
            
            # Skip wait messages
            if "wait" in content.lower() or "analyzing" in content.lower():
                continue
            
            # Apply content-specific formatting
            if any(content.startswith(prefix) for prefix in [
                "SHA256:", "Type:", "Size:", "First Seen:",
                "Last Analyzed:", "Detection Rate:", "Hash:"
            ]):
                self.write_line(content, indent=indent*3, style='key', color=self.colors['primary'])
            
            elif any(keyword in content.lower() for keyword in [
                "trojan", "malware", "virus", "malicious", "unsafe", "riskware"
            ]):
                self.write_line(content, indent=indent*3, style='warning')
            
            elif content.startswith("-"):
                bullet_content = "• " + content[1:].strip()
                self.write_line(bullet_content, indent=10, style=style)
            
            else:
                self.write_line(content, indent=indent*3, style=style) 