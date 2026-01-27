"""
Simple GUI Interface for Network Traffic Analyzer
Clean, straightforward interface with drag-and-drop support
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD
import threading
import os
import sys
from datetime import datetime
from network_analyzer import NetworkAnalyzer
from dashboard import show_dashboard


class SimpleNetworkAnalyzerGUI:
    """Simple, clean GUI for network traffic analyzer"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("900x750")
        
        # Center window
        self._center_window()
        
        self.analyzer = NetworkAnalyzer()
        self.pcap_file = None
        self.analysis_running = False
        
        # Create widgets
        self._create_widgets()
        
        # Setup drag and drop
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self._on_drop)
    
    def _center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = 900
        height = 750
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _create_widgets(self):
        """Create GUI widgets"""
        
        # Header
        header_frame = tk.Frame(self.root, bg='#4a90e2', height=70)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🔍 Network Traffic Analyzer",
            font=('Arial', 20, 'bold'),
            bg='#4a90e2',
            fg='white'
        )
        title_label.pack(pady=20)
        
        # Main container
        main_container = tk.Frame(self.root, bg='white')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # File Selection
        file_frame = tk.LabelFrame(
            main_container,
            text="Evidence File",
            font=('Arial', 11, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        file_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Drag-drop zone
        drop_zone = tk.Frame(file_frame, bg='#e8f4f8', relief='solid',
                            borderwidth=2, highlightbackground='#4a90e2',
                            highlightthickness=2)
        drop_zone.pack(fill=tk.X, pady=10)
        drop_zone.drop_target_register(DND_FILES)
        drop_zone.dnd_bind('<<Drop>>', self._on_drop)
        
        drop_label = tk.Label(
            drop_zone,
            text="📂 Drag & Drop PCAP file here or click Browse",
            font=('Arial', 11),
            bg='#e8f4f8',
            fg='#333'
        )
        drop_label.pack(pady=30)
        
        # File info
        file_info_frame = tk.Frame(file_frame, bg='white')
        file_info_frame.pack(fill=tk.X, pady=5)
        
        self.file_label = tk.Label(
            file_info_frame,
            text="No file selected",
            bg='white',
            fg='#666',
            font=('Arial', 9)
        )
        self.file_label.pack(side=tk.LEFT, padx=5)
        
        browse_btn = tk.Button(
            file_info_frame,
            text="Browse",
            command=self._browse_file,
            bg='#4a90e2',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=5,
            cursor='hand2',
            relief='flat'
        )
        browse_btn.pack(side=tk.RIGHT)
        
        # Case Information
        info_frame = tk.LabelFrame(
            main_container,
            text="Case Information",
            font=('Arial', 11, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Form fields
        tk.Label(info_frame, text="Analyst Name *", bg='white', anchor='w').grid(
            row=0, column=0, sticky=tk.W, pady=5)
        self.analyst_entry = tk.Entry(info_frame, width=45, font=('Arial', 10))
        self.analyst_entry.grid(row=0, column=1, pady=5, padx=10)
        
        tk.Label(info_frame, text="Case ID (optional)", bg='white', anchor='w').grid(
            row=1, column=0, sticky=tk.W, pady=5)
        self.case_id_entry = tk.Entry(info_frame, width=45, font=('Arial', 10))
        self.case_id_entry.grid(row=1, column=1, pady=5, padx=10)
        
        tk.Label(info_frame, text="Authorized By", bg='white', anchor='w').grid(
            row=2, column=0, sticky=tk.W, pady=5)
        self.authorized_entry = tk.Entry(info_frame, width=45, font=('Arial', 10))
        self.authorized_entry.grid(row=2, column=1, pady=5, padx=10)
        
        tk.Label(info_frame, text="Description", bg='white', anchor='w').grid(
            row=3, column=0, sticky=tk.NW, pady=5)
        self.description_text = tk.Text(info_frame, width=45, height=3, font=('Arial', 9))
        self.description_text.grid(row=3, column=1, pady=5, padx=10)
        
        # Start button
        self.analyze_btn = tk.Button(
            main_container,
            text="▶ Start Analysis",
            command=self._start_analysis,
            bg='#28a745',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=40,
            pady=12,
            cursor='hand2',
            relief='flat'
        )
        self.analyze_btn.pack(pady=15)
        
        # Progress
        progress_frame = tk.LabelFrame(
            main_container,
            text="Progress",
            font=('Arial', 11, 'bold'),
            bg='white',
            padx=15,
            pady=15
        )
        progress_frame.pack(fill=tk.BOTH, expand=True)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=400
        )
        self.progress_bar.pack(pady=5)
        
        self.progress_text = scrolledtext.ScrolledText(
            progress_frame,
            width=80,
            height=10,
            bg='#f8f8f8',
            font=('Courier', 9)
        )
        self.progress_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Status bar
        self.status_bar = tk.Label(
            self.root,
            text="Ready",
            bg='#4a90e2',
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
            self._set_file(filename)
    
    def _on_drop(self, event):
        """Handle file drop"""
        files = self.root.tk.splitlist(event.data)
        if files:
            filename = files[0]
            if filename.lower().endswith(('.pcap', '.pcapng')):
                self._set_file(filename)
            else:
                messagebox.showerror("Invalid File", 
                                   "Please select a PCAP file (.pcap or .pcapng)")
    
    def _set_file(self, filename):
        """Set selected file"""
        self.pcap_file = filename
        file_size = os.path.getsize(filename)
        size_mb = file_size / (1024 * 1024)
        self.file_label.config(
            text=f"✓ {os.path.basename(filename)} ({size_mb:.2f} MB)",
            fg='#28a745'
        )
        self._log_message(f"File selected: {filename}")
    
    def _start_analysis(self):
        """Start analysis"""
        if self.analysis_running:
            messagebox.showwarning("Running", "Analysis already in progress")
            return
        
        if not self.pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file")
            return
        
        analyst_name = self.analyst_entry.get().strip()
        if not analyst_name:
            messagebox.showerror("Error", "Please enter analyst name")
            return
        
        if not messagebox.askyesno("Confirm", 
                                   f"Start analysis of:\n{os.path.basename(self.pcap_file)}?"):
            return
        
        # Clear progress
        self.progress_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        
        # Get inputs
        case_id = self.case_id_entry.get().strip() or None
        authorized_by = self.authorized_entry.get().strip() or None
        description = self.description_text.get(1.0, tk.END).strip()
        
        # Disable button
        self.analyze_btn.config(state='disabled', bg='#ccc')
        self.analysis_running = True
        self.status_bar.config(text="Analysis in progress...", bg='#ffc107')
        
        # Run in thread
        thread = threading.Thread(
            target=self._run_analysis,
            args=(analyst_name, case_id, authorized_by, description),
            daemon=True
        )
        thread.start()
    
    def _run_analysis(self, analyst_name, case_id, authorized_by, description):
        """Run analysis in background"""
        try:
            old_stdout = sys.stdout
            sys.stdout = TextRedirector(self, self.root)
            
            self.analyzer.run_analysis(
                pcap_file=self.pcap_file,
                analyst_name=analyst_name,
                case_id=case_id,
                authorized_by=authorized_by,
                case_description=description
            )
            
            sys.stdout = old_stdout
            
            self.root.after(0, lambda: self.progress_var.set(100))
            self.root.after(0, lambda: self.status_bar.config(
                text="Complete!", bg='#28a745'))
            # Launch dashboard instead of simple messagebox
            self.root.after(0, lambda: show_dashboard(self.root, self.analyzer))
        except Exception as e:
            error_msg = str(e)  # Capture error message before lambda
            self.root.after(0, lambda: self.status_bar.config(
                text="Failed", bg='#dc3545'))
            self.root.after(0, lambda msg=error_msg: messagebox.showerror(
                "Error", f"Analysis failed:\n{msg}"))
        finally:
            self.root.after(0, lambda: self.analyze_btn.config(
                state='normal', bg='#28a745'))
            self.analysis_running = False
    
    def _log_message(self, message):
        """Log message"""
        self.progress_text.insert(tk.END, message + "\n")
        self.progress_text.see(tk.END)
        
        # Update progress bar
        if '[STEP' in message:
            try:
                step_part = message.split('[STEP')[1].split(']')[0]
                current, total = map(int, step_part.split('/'))
                progress = (current / total) * 100
                self.progress_var.set(progress)
            except:
                pass


class TextRedirector:
    """Redirect stdout to GUI"""
    
    def __init__(self, gui, root):
        self.gui = gui
        self.root = root
    
    def write(self, text):
        self.root.after(0, lambda: self.gui._log_message(text.rstrip()))
    
    def flush(self):
        pass


def launch_gui():
    """Launch GUI"""
    root = TkinterDnD.Tk()
    app = SimpleNetworkAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
