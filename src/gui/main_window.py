import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from config import Config
from src.analyzers.pe_analyzer import PEAnalyzer
from src.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from src.analyzers.DynamicAnalysis import DynamicAnalyzer
from src.utils.report_generator import PDFReportGenerator

class HashInputDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text="Enter hash code:").grid(row=0, column=0, padx=5, pady=5)
        self.hash_entry = ttk.Entry(master, width=70)
        self.hash_entry.grid(row=0, column=1, padx=5, pady=5)
        return self.hash_entry

    def apply(self):
        self.result = self.hash_entry.get().strip()

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("PE File Analyzer")
        self.root.geometry("1200x800")
        
        self.pe_analyzer = PEAnalyzer()
        self.vt_analyzer = VirusTotalAnalyzer()
        self.current_file = None
        
        self.setup_gui()

    def setup_gui(self):
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.top_frame = ttk.Frame(self.main_container)
        self.top_frame.pack(fill=tk.X, padx=5, pady=5)

        self.setup_filter_frame()
        self.setup_output_frame()
        self.setup_buttons()

    def setup_filter_frame(self):
        self.filter_frame = ttk.Frame(self.top_frame)
        self.filter_var = tk.StringVar(value="All")
        
        filter_label = ttk.Label(self.filter_frame, text="String Filter:")
        filter_label.pack(side=tk.LEFT, padx=5)
        
        self.filter_combo = ttk.Combobox(
            self.filter_frame, 
            textvariable=self.filter_var,
            values=list(Config.FILTERS.keys()),
            state="readonly",
            width=20
        )
        self.filter_combo.pack(side=tk.LEFT, padx=5)
        
        self.apply_filter_btn = ttk.Button(
            self.filter_frame,
            text="Apply Filter",
            command=self.refresh_strings
        )
        self.apply_filter_btn.pack(side=tk.LEFT, padx=5)

    def setup_output_frame(self):
        output_frame = ttk.Frame(self.main_container)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.output_text = tk.Text(output_frame, wrap=tk.WORD, font=("Courier", 10))
        scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def setup_buttons(self):
        ttk.Button(self.top_frame, text="📁 Static Analysis", 
                   command=self.do_static_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.top_frame, text="🔬 VirusTotal Analysis", 
                   command=self.do_virustotal_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.top_frame, text="🧪 Dynamic Analysis",
                   command=self.do_dynamic_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.top_frame, text="📄 Export PDF", 
                   command=self.export_pdf).pack(side=tk.LEFT, padx=5)

    def format_section_header(self, title):
        width = 80
        padding = (width - len(title) - 2) // 2
        return f"\n{'='*width}\n{' '*padding}{title}\n{'='*width}\n"

    def do_static_analysis(self):
        file_path = filedialog.askopenfilename(
            title="Select PE File",
            filetypes=[("Executable Files", "*.exe *.dll"), ("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            self.current_file = file_path
            analysis_results = self.pe_analyzer.load_file(file_path)
            self.display_pe_analysis(analysis_results)
            self.filter_frame.pack(side=tk.RIGHT, padx=5)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")

    def display_pe_analysis(self, results):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, self.format_section_header("File Information"))
        
        for key, value in results['basic_info'].items():
            self.output_text.insert(tk.END, f"{key}: {value}\n")
        
        self.output_text.insert(tk.END, self.format_section_header("File Hashes"))
        for hash_type, hash_value in results['hashes'].items():
            self.output_text.insert(tk.END, f"{hash_type}: {hash_value}\n")
        
        self.output_text.insert(tk.END, self.format_section_header("PE Header Information"))
        for info in results['pe_info']:
            self.output_text.insert(tk.END, f"{info}\n")
        
        self.output_text.insert(tk.END, self.format_section_header("PE Sections"))
        for section in results['sections']:
            self.output_text.insert(tk.END, f"Section: {section['name']}\n")
            self.output_text.insert(tk.END, f"  Virtual Address: {section['virtual_addr']}\n")
            self.output_text.insert(tk.END, f"  Virtual Size: {section['virtual_size']}\n")
            self.output_text.insert(tk.END, f"  Raw Size: {section['raw_size']}\n\n")
        
        if results.get('imports'):
            self.output_text.insert(tk.END, self.format_section_header("Imported DLLs and Functions"))
            for imp in results['imports']:
                self.output_text.insert(tk.END, f"\n📚 {imp['dll']}\n")
                for func in imp['functions']:
                    self.output_text.insert(tk.END, f"  → {func}\n")

        if results.get('exports'):
            self.output_text.insert(tk.END, self.format_section_header("Exported Functions"))
            for exp in results['exports']:
                self.output_text.insert(tk.END, f"  {exp['name']} @ {exp['address']}\n")

        self.refresh_strings()

    def refresh_strings(self):
        if not hasattr(self.pe_analyzer, 'filepath') or not self.pe_analyzer.filepath:
            return

        content = self.output_text.get(1.0, tk.END)
        start = content.find("Extracted Strings")
        if start != -1:
            self.output_text.delete(f"1.0 + {start} chars", tk.END)

        self.output_text.insert(tk.END, self.format_section_header("Extracted Strings"))
        strings = self.pe_analyzer.extract_strings(filter_name=self.filter_var.get())
        if self.filter_var.get() == "IPs":
            if strings:
                self.output_text.insert(tk.END, "  IP Addresses found:\n")
                for ip in strings[:100]:
                    self.output_text.insert(tk.END, f"    • {ip}\n")
                if len(strings) > 100:
                    self.output_text.insert(tk.END, f"\n[+] ... and {len(strings) - 100} more IPs not shown.\n")
            else:
                self.output_text.insert(tk.END, "  No IP addresses found.\n")
        else:
            for idx, s in enumerate(strings[:100], 1):
                self.output_text.insert(tk.END, f"  {idx}. {s}\n")
            if len(strings) > 100:
                self.output_text.insert(tk.END, f"\n[+] ... and {len(strings) - 100} more strings not shown.\n")

    def do_virustotal_analysis(self):
        if self.current_file:
            file_hash = self.pe_analyzer.hashes['SHA256']
        else:
            dialog = HashInputDialog(self.root, title="VirusTotal Hash Search")
            if not dialog.result:
                return
            file_hash = dialog.result

        try:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, self.format_section_header("VirusTotal Analysis"))
            self.output_text.insert(tk.END, f"Analyzing hash: {file_hash}\nPlease wait...\n")
            self.root.update()

            result = self.vt_analyzer.get_report(file_hash)
            if result:
                self.display_vt_results(result)
            else:
                self.output_text.insert(tk.END, "No results found on VirusTotal.\n")
        except Exception as e:
            messagebox.showerror("Error", f"VirusTotal analysis failed: {str(e)}")

    def display_vt_results(self, results):
        self.output_text.insert(tk.END, self.format_section_header("Basic Information"))
        self.output_text.insert(tk.END, f"SHA256: {results['hash']}\n")
        self.output_text.insert(tk.END, f"Type: {results['type']}\n")
        self.output_text.insert(tk.END, f"Size: {results['size']} bytes\n")
        self.output_text.insert(tk.END, f"First Seen: {time.strftime('%Y-%m-%d', time.localtime(results['first_seen']))}\n")
        self.output_text.insert(tk.END, f"Last Analyzed: {time.strftime('%Y-%m-%d', time.localtime(results['last_seen']))}\n")
        self.output_text.insert(tk.END, f"Detection Rate: {results['malicious_count']} / {results['total_engines']}\n")

        if results['names']:
            self.output_text.insert(tk.END, self.format_section_header("Known Names"))
            for name in results['names'][:5]:
                self.output_text.insert(tk.END, f"  - {name}\n")

        self.output_text.insert(tk.END, self.format_section_header("Malicious Detections"))
        for engine, result in results['analysis_results'].items():
            if result.get('category') == 'malicious':
                self.output_text.insert(tk.END, f"  - {engine}: {result.get('result', 'N/A')}\n")

    def do_dynamic_analysis(self):
        if not self.current_file:
            file_path = filedialog.askopenfilename(
                title="Select File for Dynamic Analysis",
                filetypes=[("Executable Files", "*.exe *.dll"), ("All files", "*.*")]
            )
            if not file_path:
                return
        else:
            file_path = self.current_file

        try:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, self.format_section_header("Dynamic Analysis"))
            self.output_text.insert(tk.END, "Submitting file to Hybrid Analysis...\nPlease wait, this may take a few minutes.\n")
            self.root.update()

            analyzer = DynamicAnalyzer()
            result = analyzer.analyze_file(file_path)
            
            if result['success']:
                self.display_dynamic_analysis(result['data'])
            else:
                self.output_text.insert(tk.END, f"\nAnalysis failed: {result['error']}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Dynamic analysis failed: {str(e)}")

    def display_dynamic_analysis(self, results):
        self.output_text.delete(1.0, tk.END)
        
        # Display Basic Information
        self.output_text.insert(tk.END, self.format_section_header("Basic Information"))
        for key, value in results['basic_info'].items():
            self.output_text.insert(tk.END, f"{key}: {value}\n")
        
        # Display Signatures
        if results['signatures']:
            self.output_text.insert(tk.END, self.format_section_header("Detected Signatures"))
            for sig in results['signatures']:
                self.output_text.insert(tk.END, f"Name: {sig.get('name', 'Unknown')}\n")
                if sig.get('description'):
                    self.output_text.insert(tk.END, f"Description: {sig.get('description')}\n")
                self.output_text.insert(tk.END, "-" * 40 + "\n")
        
        # Display Processes
        if results['processes']:
            self.output_text.insert(tk.END, self.format_section_header("Processes"))
            for proc in results['processes']:
                self.output_text.insert(tk.END, f"Process: {proc.get('process_name', 'Unknown')}\n")
                if proc.get('command_line'):
                    self.output_text.insert(tk.END, f"Command Line: {proc.get('command_line')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display Network Activity
        if results['network_hosts']:
            self.output_text.insert(tk.END, self.format_section_header("Network Activity"))
            for host in results['network_hosts']:
                hostname = host.get('hostname') or host.get('ip', 'Unknown')
                self.output_text.insert(tk.END, f"Host: {hostname}\n")
                if host.get('port'):
                    self.output_text.insert(tk.END, f"Port: {host['port']}\n")
                if host.get('protocol'):
                    self.output_text.insert(tk.END, f"Protocol: {host['protocol']}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display URLs
        if results['extracted_urls']:
            self.output_text.insert(tk.END, self.format_section_header("Extracted URLs"))
            for url in results['extracted_urls']:
                self.output_text.insert(tk.END, f"• {url}\n")
        
        # Display MITRE ATT&CK
        if results['mitre_attacks']:
            self.output_text.insert(tk.END, self.format_section_header("MITRE ATT&CK Techniques"))
            for attack in results['mitre_attacks']:
                self.output_text.insert(tk.END, f"Technique: {attack.get('technique', 'Unknown')}\n")
                if attack.get('description'):
                    self.output_text.insert(tk.END, f"Description: {attack.get('description')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display Dropped Files
        if results['dropped_files']:
            self.output_text.insert(tk.END, self.format_section_header("Dropped Files"))
            for file in results['dropped_files']:
                self.output_text.insert(tk.END, f"Name: {file.get('name', 'Unknown')}\n")
                if file.get('type'):
                    self.output_text.insert(tk.END, f"Type: {file.get('type')}\n")
                if file.get('sha256'):
                    self.output_text.insert(tk.END, f"SHA256: {file.get('sha256')}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Display Interesting Behaviors
        if results['interesting_behaviors']:
            self.output_text.insert(tk.END, self.format_section_header("Interesting Behaviors"))
            for key, value in results['interesting_behaviors'].items():
                self.output_text.insert(tk.END, f"{key}:\n{value}\n\n")

    def export_pdf(self):
        try:
            os.makedirs(Config.OUTPUT_FOLDER, exist_ok=True)
            current_content = self.output_text.get(1.0, tk.END)
            if not current_content.strip():
                messagebox.showwarning("Warning", "No content to export.")
                return

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"analysis_report_{timestamp}.pdf"
            filepath = os.path.join(Config.OUTPUT_FOLDER, filename)
            report = PDFReportGenerator(filepath)
            report.generate_from_text(current_content)
            
            messagebox.showinfo("Success", f"Report saved as {filename} in output_pdf directory")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export PDF: {str(e)}") 