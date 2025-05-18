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

        # --- Main container and output frame ---
        self.pe_analyzer = PEAnalyzer()
        self.vt_analyzer = VirusTotalAnalyzer()
        self.current_file = None

        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=5, pady=5)
        self.setup_output_frame()

    def toggle_mode(self):
        mode = self.appearance_switch.get()
        ctk.set_appearance_mode("Dark" if mode else "Light")
        self.update_output_text_theme()

    def setup_output_frame(self):
        # For the main output panel/frame:
        self.output_panel = ctk.CTkFrame(
            self.main_container,
            fg_color=("#fff", "#23272f"),         # light, dark
            border_color=("#ccc", "#181a20"),
            border_width=2,
            corner_radius=10
        )
        self.output_panel.pack(fill="both", expand=True, padx=10, pady=10)

        # For the output textbox:
        self.output_text = ctk.CTkTextbox(
            self.output_panel,
            fg_color="transparent",               # inherits from parent
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
        # If no sample, prompt for hash
        if not self.current_file:
            hash_dialog = HashInputDialog(self.root)
            file_hash = hash_dialog.result
            if not file_hash:
                self.output_text.delete(1.0, "end")
                self.output_text.insert("end", "No hash provided. Operation cancelled.")
                return
        else:
            # Ask user: use sample or enter hash?
            choice = messagebox.askyesno(
                "VirusTotal Analysis",
                "Use uploaded sample's hash?\n\nYes: Use uploaded sample\nNo: Enter a hash manually"
            )
            if choice:
                # Use uploaded sample's hash
                file_hash = self.pe_analyzer.hashes.get('SHA256')
                if not file_hash:
                    self.output_text.delete(1.0, "end")
                    self.output_text.insert("end", "No SHA256 hash found. Please run static analysis first.")
                    return
            else:
                # Prompt for hash
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