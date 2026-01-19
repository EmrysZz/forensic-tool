"""
GUI Interface for Network Traffic Analyzer
Provides user-friendly graphical interface for forensic analysis
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
from network_analyzer import NetworkAnalyzer


class NetworkAnalyzerGUI:
    """Graphical user interface for network traffic analyzer"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer - Digital Forensic Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        self.analyzer = NetworkAnalyzer()
        self.pcap_file = None
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create GUI widgets"""
        
        # Header
        header_frame = tk.Frame(self.root, bg='#667eea', height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🔍 Network Traffic Analyzer",
            font=('Arial', 24, 'bold'),
            bg='#667eea',
            fg='white'
        )
        title_label.pack(pady=20)
        
        # Main container
        main_container = tk.Frame(self.root, bg='#f0f0f0')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # File Selection Section
        file_frame = tk.LabelFrame(
            main_container,
            text="1. Evidence File",
            font=('Arial', 12, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        file_frame.pack(fill=tk.X, pady=10)
        
        self.file_label = tk.Label(
            file_frame,
            text="No file selected",
            bg='white',
            fg='#666'
        )
        self.file_label.pack(side=tk.LEFT, padx=5)
        
        browse_btn = tk.Button(
            file_frame,
            text="📁 Browse PCAP File",
            command=self._browse_file,
            bg='#667eea',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=5,
            cursor='hand2'
        )
        browse_btn.pack(side=tk.RIGHT)
        
        # Case Information Section
        info_frame = tk.LabelFrame(
            main_container,
            text="2. Case Information",
            font=('Arial', 12, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        info_frame.pack(fill=tk.X, pady=10)
        
        # Analyst Name
        tk.Label(info_frame, text="Analyst Name:", bg='white').grid(row=0, column=0, sticky=tk.W, pady=5)
        self.analyst_entry = tk.Entry(info_frame, width=40)
        self.analyst_entry.grid(row=0, column=1, pady=5, padx=10)
        
        # Case ID
        tk.Label(info_frame, text="Case ID (optional):", bg='white').grid(row=1, column=0, sticky=tk.W, pady=5)
        self.case_id_entry = tk.Entry(info_frame, width=40)
        self.case_id_entry.grid(row=1, column=1, pady=5, padx=10)
        
        # Authorized By
        tk.Label(info_frame, text="Authorized By:", bg='white').grid(row=2, column=0, sticky=tk.W, pady=5)
        self.authorized_entry = tk.Entry(info_frame, width=40)
        self.authorized_entry.grid(row=2, column=1, pady=5, padx=10)
        
        # Case Description
        tk.Label(info_frame, text="Description:", bg='white').grid(row=3, column=0, sticky=tk.NW, pady=5)
        self.description_text = tk.Text(info_frame, width=40, height=3)
        self.description_text.grid(row=3, column=1, pady=5, padx=10)
        
        # Analysis Button
        analyze_btn = tk.Button(
            main_container,
            text="▶ Start Forensic Analysis",
            command=self._start_analysis,
            bg='#28a745',
            fg='white',
            font=('Arial', 14, 'bold'),
            padx=40,
            pady=15,
            cursor='hand2'
        )
        analyze_btn.pack(pady=20)
        
        # Progress Section
        progress_frame = tk.LabelFrame(
            main_container,
            text="Analysis Progress",
            font=('Arial', 12, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        progress_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.progress_text = scrolledtext.ScrolledText(
            progress_frame,
            width=80,
            height=15,
            bg='#f8f9fa',
            font=('Courier', 9)
        )
        self.progress_text.pack(fill=tk.BOTH, expand=True)
        
        # Status Bar
        self.status_bar = tk.Label(
            self.root,
            text="Ready",
            bg='#667eea',
            fg='white',
            anchor=tk.W,
            padx=10
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _browse_file(self):
        """Browse for PCAP file"""
        filename = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP Files", "*.pcap *.pcapng"), ("All Files", "*.*")]
        )
        
        if filename:
            self.pcap_file = filename
            self.file_label.config(text=os.path.basename(filename), fg='#28a745')
            self.log_message(f"Selected file: {filename}")
    
    def _start_analysis(self):
        """Start forensic analysis"""
        
        # Validate inputs
        if not self.pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file")
            return
        
        analyst_name = self.analyst_entry.get().strip()
        if not analyst_name:
            messagebox.showerror("Error", "Please enter analyst name")
            return
        
        # Confirm start
        if not messagebox.askyesno(
            "Confirm Analysis",
            "Start forensic analysis?\n\nThis will process the PCAP file and generate comprehensive reports."
        ):
            return
        
        # Clear previous progress
        self.progress_text.delete(1.0, tk.END)
        
        # Get inputs
        case_id = self.case_id_entry.get().strip() or None
        authorized_by = self.authorized_entry.get().strip() or None
        description = self.description_text.get(1.0, tk.END).strip()
        
        # Run analysis in separate thread
        self.status_bar.config(text="Analysis in progress...", bg='#ffc107')
        
        thread = threading.Thread(
            target=self._run_analysis_thread,
            args=(analyst_name, case_id, authorized_by, description)
        )
        thread.daemon = True
        thread.start()
    
    def _run_analysis_thread(self, analyst_name, case_id, authorized_by, description):
        """Run analysis in background thread"""
        
        try:
            # Redirect output to GUI
            import sys
            from io import StringIO
            
            old_stdout = sys.stdout
            sys.stdout = TextRedirector(self.progress_text, self.root)
            
            # Run analysis
            self.analyzer.run_analysis(
                pcap_file=self.pcap_file,
                analyst_name=analyst_name,
                case_id=case_id,
                authorized_by=authorized_by,
                case_description=description
            )
            
            sys.stdout = old_stdout
            
            # Show completion message
            self.root.after(
                0,
                lambda: self.status_bar.config(text="Analysis complete!", bg='#28a745')
            )
            
            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Analysis Complete",
                    f"Forensic analysis completed successfully!\n\nReports saved to: reports/{self.analyzer.case_id}/"
                )
            )
            
        except Exception as e:
            self.root.after(
                0,
                lambda: self.status_bar.config(text="Analysis failed", bg='#dc3545')
            )
            self.root.after(
                0,
                lambda: messagebox.showerror("Error", f"Analysis failed:\n{str(e)}")
            )
    
    def log_message(self, message):
        """Log message to progress window"""
        self.progress_text.insert(tk.END, message + "\n")
        self.progress_text.see(tk.END)


class TextRedirector:
    """Redirects print output to Text widget"""
    
    def __init__(self, widget, root):
        self.widget = widget
        self.root = root
    
    def write(self, text):
        self.root.after(0, lambda: self.widget.insert(tk.END, text))
        self.root.after(0, lambda: self.widget.see(tk.END))
    
    def flush(self):
        pass


def launch_gui():
    """Launch the GUI application"""
    root = tk.Tk()
    app = NetworkAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
