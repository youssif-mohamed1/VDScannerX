import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import customtkinter as ctk
from config import Config
from src.analyzers.pe_analyzer import PEAnalyzer
from src.analyzers.virustotal_analyzer import VirusTotalAnalyzer
from src.analyzers.DynamicAnalysis import DynamicAnalyzer
from src.utils.report_generator import PDFReportGenerator
from src.utils.html_generator import HTMLReportGenerator
import webbrowser

class HashInputDialog(simpledialog.Dialog):
    def body(self, master):
        self.label = ctk.CTkLabel(master, text="Enter hash code:")
        self.label.grid(row=0, column=0, padx=5, pady=5)

        self.hash_entry = ctk.CTkEntry(master, width=400)
        self.hash_entry.grid(row=0, column=1, padx=5, pady=5)
        return self.hash_entry

    def apply(self):
        self.result = self.hash_entry.get().strip()

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("VDScannerX")
        self.root.geometry("900x600")
        self.root.resizable(True, True)  # Allow maximization

        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")

        # --- Top frame for dark mode toggle (top right) ---
        self.top_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.top_frame.pack(fill="x", pady=(10, 0), padx=10)
        self.appearance_switch = ctk.CTkSwitch(
            self.top_frame, text="🌗 Dark Mode", command=self.toggle_mode
        )
        self.appearance_switch.pack(side="right", padx=0)

        # --- Title label (centered, below toggle) ---
        self.label = ctk.CTkLabel(
            self.root,
            text="VDScannerX: Analyze. Detect. Understand",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.label.pack(pady=(10, 2))

        # --- Frame for buttons and filter bar (below the title) ---
        self.button_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.button_frame.pack(fill="x", pady=(10, 10), padx=10)

        # Upload button (add this before the analysis buttons)
        ctk.CTkButton(
            self.button_frame,
            text="⬆ Upload",
            command=self.upload_sample,
            width=90, height=32
        ).pack(side="left", padx=3)

        # Analysis buttons (smaller width)
        ctk.CTkButton(self.button_frame, text="📁 Static", 
                    command=self.do_static_analysis, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="🔬 VT", 
                    command=self.do_virustotal_analysis, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="🧪 Dynamic",
                    command=self.do_dynamic_analysis, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="📄 PDF", 
                    command=self.export_pdf, width=100, height=32).pack(side="left", padx=3)
        ctk.CTkButton(self.button_frame, text="🌐 Export HTML", 
                    command=self.export_html, width=100, height=32).pack(side="left", padx=3)

        # Filter bar and Apply Filter button (in button_frame)
        self.filter_var = tk.StringVar(value="All")
        ctk.CTkLabel(self.button_frame, text="String Filter:").pack(side="left", padx=5)
        self.filter_combo = ctk.CTkComboBox(
            self.button_frame,
            variable=self.filter_var,
            values=list(Config.FILTERS.keys()),
            width=100
        )
        self.filter_combo.pack(side="left", padx=3)
        ctk.CTkButton(
            self.button_frame,
            text="Apply",
            command=self.refresh_strings,
            width=70, height=32
        ).pack(side="left", padx=3)

        # Initialize analyzers 

        self.pe_analyzer = PEAnalyzer()
        self.vt_analyzer = VirusTotalAnalyzer()
        self.current_file = None

        # --- Main container and output frame ---
        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=5, pady=5)
        self.setup_output_frame()

    def toggle_mode(self):
        mode = self.appearance_switch.get()
        ctk.set_appearance_mode("Dark" if mode else "Light")
        self.update_output_text_theme()

    def setup_output_frame(self):
        self.output_panel = ctk.CTkFrame(
            self.main_container,
            fg_color=("#fff", "#23272f"),         # light, dark
            border_color=("#ccc", "#181a20"),
            border_width=2,
            corner_radius=10
        )
        self.output_panel.pack(fill="both", expand=True, padx=10, pady=10)

        self.output_text = ctk.CTkTextbox(
            self.output_panel,
            fg_color="transparent",               
            text_color=("#222", "#fff"),
            font=("Consolas", 12)
        )
        self.output_text.pack(fill="both", expand=True, padx=8, pady=8)

    def format_section_header(self, title):
        width = 80
        padding = (width - len(title) - 2) // 2
        return f"\n{'='*width}\n{' '*padding}{title}\n{'='*width}\n"

    def do_static_analysis(self):
        if not self.current_file:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", "Please upload a sample first using the Upload button.")
            return
        try:
            analysis_results = self.pe_analyzer.load_file(self.current_file)
            self.display_pe_analysis(analysis_results)
        except Exception as e:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"Failed to analyze file: {str(e)}")

    def display_pe_analysis(self, results):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, self.format_section_header("Static Analysis"))
        self.output_text.insert(tk.END, f"File: {self.current_file}\n")
        
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
        if not self.current_file:
            #then get the hash from the user
            hash_dialog = HashInputDialog(self.root)
            file_hash = hash_dialog.result
            #if the hash is not provided, then show a message and terminate  the function
            if not file_hash:
                self.output_text.delete(1.0, "end") 
                self.output_text.insert("end", "No hash provided. Operation cancelled.")
                return
        else:
            choice = messagebox.askyesno(
                "VirusTotal Analysis",
                "Use uploaded sample's hash?\n\nYes: Use uploaded sample\nNo: Enter a hash manually"
            )
            #if the user chooses(i mean if the user clicks on yes) to use the uploaded sample, then get the hash from the pe_analyzer
            if choice:
                file_hash = self.pe_analyzer.hashes.get('SHA256')
                if not file_hash:
                    self.output_text.delete(1.0, "end")
                    self.output_text.insert("end", "No SHA256 hash found. Please run static analysis first.")
                    return
            else:
                hash_dialog = HashInputDialog(self.root)
                file_hash = hash_dialog.result
                if not file_hash:
                    self.output_text.delete(1.0, "end")
                    self.output_text.insert("end", "No hash provided. Operation cancelled.")
                    return

        try:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", self.format_section_header("VirusTotal Analysis"))
            self.output_text.insert("end", f"Analyzing hash: {file_hash}\nPlease wait...\n")
            self.root.update()

            result = self.vt_analyzer.get_report(file_hash)
            if result:
                self.display_vt_results(result)
            else:
                self.output_text.insert("end", "No results found on VirusTotal.\n")
        except Exception as e:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"VirusTotal analysis failed: {str(e)}")

    def display_vt_results(self, results):
        self.output_text.insert(tk.END, self.format_section_header("Basic Information"))
        self.output_text.insert(tk.END, f"SHA256: {results['hash']}\n")
        self.output_text.insert(tk.END, f"Type: {results['type']}\n")
        self.output_text.insert(tk.END, f"Size: {results['size']} bytes\n")
        self.output_text.insert(tk.END, f"First Seen: {time.strftime('%Y-%m-%d', time.localtime(results['first_seen']))}\n")
        self.output_text.insert(tk.END, f"Last Analyzed: {time.strftime('%Y-%m-%d', time.localtime(results['last_seen']))}\n")
        self.output_text.insert(tk.END, f"Detection Rate: {results['malicious_count']} / {results['total_engines']}\n")
        #analysis statistics
        self.output_text.insert(tk.END, self.format_section_header("Analysis Statistics"))
        stats = results['analysis_stats']
        self.output_text.insert(tk.END, f"Malicious: {stats.get('malicious', 0)}\n")
        self.output_text.insert(tk.END, f"Suspicious: {stats.get('suspicious', 0)}\n")
        self.output_text.insert(tk.END, f"Undetected: {stats.get('undetected', 0)}\n")
        self.output_text.insert(tk.END, f"Harmless: {stats.get('harmless', 0)}\n")
        self.output_text.insert(tk.END, f"Timeout: {stats.get('timeout', 0)}\n")
        self.output_text.insert(tk.END, f"Type Unsupported: {stats.get('type-unsupported', 0)}\n")

        if results['names']:
            self.output_text.insert(tk.END, self.format_section_header("Known Names"))
            for name in results['names'][:5]:
                self.output_text.insert(tk.END, f"  - {name}\n")

        self.output_text.insert(tk.END, self.format_section_header("Malicious Detections"))
        for engine, result in results['analysis_results'].items():
            if result.get('category') == 'malicious':
                self.output_text.insert(tk.END, f"  - {engine}: {result.get('result', 'N/A')}\n")

        # Undetected Engines
        self.output_text.insert(tk.END, self.format_section_header("Undetected Engines"))
        for engine, result in results['analysis_results'].items():
            if result.get('category') == 'undetected':
                self.output_text.insert(tk.END, f"  - {engine} (version: {result.get('engine_version', 'N/A')})\n")

    def do_dynamic_analysis(self):
        if not self.current_file:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", "Please upload a sample first using the Upload button.")
            return
        try:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", self.format_section_header("Dynamic Analysis"))
            self.output_text.insert("end", "Submitting file to Hybrid Analysis...\nPlease wait, this may take a few minutes.\n")
            self.root.update()

            analyzer = DynamicAnalyzer()
            result = analyzer.analyze_file(self.current_file)
            if result['success']:
                self.display_dynamic_analysis(result['data'])
            else:
                self.output_text.insert("end", f"\nAnalysis failed: {result['error']}\n")
        except Exception as e:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"Dynamic analysis failed: {str(e)}")

    def display_dynamic_analysis(self, results):
        self.output_text.delete(1.0, tk.END)
        
        # Display Basic Information: al SUMMARY sandbox info , file info ...
        self.output_text.insert(tk.END, self.format_section_header("Basic Information"))
        for key, value in results.get('basic_info', {}).items():
            self.output_text.insert(tk.END, f"{key}: {value}\n")
        
        # 1. Display Dropped Files section: Ay files 7slha drop
        self.output_text.insert(tk.END, self.format_section_header("Dropped Files"))
        dropped_files = results.get('dropped_files', [])
        if not dropped_files:
            self.output_text.insert(tk.END, "No dropped files detected.\n")
        else:
            for file in dropped_files:
                if isinstance(file, dict):
                    self.output_text.insert(tk.END, f"Name: {file.get('name', 'Unknown')}\n")
                    if file.get('type'):
                        self.output_text.insert(tk.END, f"Type: {file.get('type')}\n")
                    if file.get('sha256'):
                        self.output_text.insert(tk.END, f"SHA256: {file.get('sha256')}\n")
                    self.output_text.insert(tk.END, "\n")
                else:
                    self.output_text.insert(tk.END, f"File data: {file}\n\n")
        
        # 2. Display Processes section :al processes al a4t8lt m3ah
        self.output_text.insert(tk.END, self.format_section_header("Processes"))
        processes = results.get('processes', [])
       
        if not processes:
            self.output_text.insert(tk.END, "No process information available.\n")
        else:
            for proc in processes:                    
                self.output_text.insert(tk.END, f"uid: {proc.get('uid', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"parentuid: {proc.get('parentuid', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"name: {proc.get('name', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"normalized_path: {proc.get('normalized_path', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"command_line: {proc.get('command_line', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"sha256: {proc.get('sha256', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"av_label: {proc.get('av_label', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"av_matched: {proc.get('av_matched', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"av_total: {proc.get('av_total', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"pid: {proc.get('pid', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"icon: {proc.get('icon', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"file_accesses: {proc.get('file_accesses', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"created_files: {proc.get('created_files', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"registry:{proc.get('registry', 'Unknown')}\n")   
                self.output_text.insert(tk.END, f"mutants:{proc.get('mutants', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"handles:{proc.get('handles', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"streams:{proc.get('streams', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"script_calls:{proc.get('script_calls', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"process_flags:{proc.get('process_flags', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"amsi_calls:{proc.get('amsi_calls', 'Unknown')}\n") 
                self.output_text.insert(tk.END, f"modules:{proc.get('modules', 'Unknown')}\n")    
                self.output_text.insert(tk.END, "\n")

        # 3. Display MITRE ATT&CK section: eh pattern al attack al 7slt w hwa Knwoledge base
        self.output_text.insert(tk.END, self.format_section_header("MITRE ATT&CK Techniques"))
        mitre_attacks = results.get('mitre_attacks', [])
        if not mitre_attacks:
            self.output_text.insert(tk.END, "No MITRE ATT&CK techniques detected.\n")
        else:
            for attack in mitre_attacks:
                
                self.output_text.insert(tk.END, "-" * 40 + "\n")

                self.output_text.insert(tk.END, f"Tactic: {attack.get('tactic', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Technique: {attack.get('technique', 'Unknown')}\n")
                if attack.get('attck_id'):
                    self.output_text.insert(tk.END, f"ID: {attack.get('attck_id')}\n")
                if attack.get('attck_id_wiki'):
                    self.output_text.insert(tk.END, f"Wiki: {attack.get('attck_id_wiki')}\n")                   # Show identifier counts
                if 'malicious_identifiers_count' in attack:
                    self.output_text.insert(tk.END, f"Malicious Indicators: {attack.get('malicious_identifiers_count')}\n")
                if 'suspicious_identifiers_count' in attack:
                    self.output_text.insert(tk.END, f"Suspicious Indicators: {attack.get('suspicious_identifiers_count')}\n")
                if 'informative_identifiers_count' in attack:
                    self.output_text.insert(tk.END, f"Informative Indicators: {attack.get('informative_identifiers_count')}\n")
                if attack.get('description'):
                    self.output_text.insert(tk.END, f"Description: {attack.get('description')}\n")
                # self.output_text.insert(tk.END, "\n")
            # else:
            #     self.output_text.insert(tk.END, f"MITRE data: {attack}\n\n")
    
    # 4. Display Network Activity section: ay IPs r7lha w al hosts
        # if(results.get('network', [])):
        #     self.output_text.insert(tk.END, self.format_section_header("Network Activity"))
        #     network_hosts = results.get('network_hosts', [])
        # else:
        #     if not network_hosts:
        #      self.output_text.insert(tk.END, "No network activity detected.\n")
        #     else:
        #         for host in network_hosts:
        #             hostname = host.get('hostname') or host.get('ip', 'Unknown')
        #             self.output_text.insert(tk.END, f"Host: {hostname}\n")
        #             if host.get('port'):
        #                 self.output_text.insert(tk.END, f"Port: {host['port']}\n")
        #             if host.get('protocol'):
        #                 self.output_text.insert(tk.END, f"Protocol: {host['protocol']}\n")
        #             self.output_text.insert(tk.END, "\n")
        
        # 5. Display Signatures grouped by category: mt2smen Categories w bt3rd kza 7aga ex: -process created, -file created, -Memory Usage
        if results.get('signatures'):
            self.output_text.insert(tk.END, self.format_section_header("Detected Signatures"))
            
            # Group signatures by category
            signatures_by_category = {}
            for sig in results.get('signatures', []):
                category = sig.get('category', 'Uncategorized')
                if category not in signatures_by_category:
                    signatures_by_category[category] = []
                signatures_by_category[category].append(sig)
            
            # Display signatures by category
            for category, sigs in signatures_by_category.items():
                self.output_text.insert(tk.END, f"\n【 {category} 】\n")
                self.output_text.insert(tk.END, "-" * 40 + "\n")
                
                for sig in sigs:
                    self.output_text.insert(tk.END, f"Name: {sig.get('name', 'Unknown')}\n")
                    self.output_text.insert(tk.END, f"Threat Level: {sig.get('threat_level', 'Unknown')}\n")
                    self.output_text.insert(tk.END, f"Threat Level Human: {sig.get('threat_level_human', 'Unknown')}\n")
                    if sig.get('description'):
                        self.output_text.insert(tk.END, f"Description: {sig.get('description')}\n")
                    self.output_text.insert(tk.END, "-" * 40 + "\n")
        
        # Display URLs section
        # if(results.get('extracted_urls', [])):
        #     self.output_text.insert(tk.END, self.format_section_header("Extracted URLs"))
        #     extracted_urls = results.get('extracted_urls', [])
        # if not extracted_urls:
        #     self.output_text.insert(tk.END, "No URLs detected.\n")
        # else:
        #     for url in extracted_urls:
        #         self.output_text.insert(tk.END, f"• {url}\n")
        
        # Display Interesting Behaviors section
        # self.output_text.insert(tk.END, self.format_section_header("Interesting Behaviors"))
        # interesting_behaviors = results.get('interesting_behaviors', {})
        # if not isinstance(interesting_behaviors, dict) or not interesting_behaviors:
        #     self.output_text.insert(tk.END, "No interesting behaviors detected.\n")
        # else:
        #     for key, value in interesting_behaviors.items():
        #         self.output_text.insert(tk.END, f"{key}:\n{value}\n\n")

                
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

    def export_html(self):
        try:
            current_content = self.output_text.get(1.0, tk.END)
            if not current_content.strip():
                messagebox.showwarning("Warning", "No content to export.")
                return

            html_generator = HTMLReportGenerator()
            output_file = html_generator.generate_from_text(current_content)
            
            webbrowser.open('file://' + os.path.realpath(output_file))
            
            messagebox.showinfo("Success", f"HTML report saved and opened in browser:\n{os.path.basename(output_file)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export HTML: {str(e)}")

    def update_output_text_theme(self):
        # Detect current mode
        mode = ctk.get_appearance_mode()
        if mode == "Dark":
            self.output_text.config(bg="#23272f", fg="#f5f5f5", insertbackground="#f5f5f5")
        else:
            self.output_text.config(bg="#ffffff", fg="#222222", insertbackground="#222222")

    def upload_sample(self):
        file_path = filedialog.askopenfilename(
            title="Select Sample File",
            filetypes=[("Executable Files", "*.exe *.dll"), ("All files", "*.*")]
        )
        if file_path:
            self.current_file = file_path
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", f"Sample uploaded:\n{file_path}\n\nReady for analysis.")
        else:
            self.output_text.delete(1.0, "end")
            self.output_text.insert("end", "No sample selected.")