"""
Enhanced GUI Interface for Network Traffic Analyzer
Modern, professional desktop interface with improved UX and visual design
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD
import threading
import os
import sys
from datetime import datetime
from network_analyzer import NetworkAnalyzer


class ModernButton(tk.Canvas):
    """Custom modern-looking button with hover effects"""
    
    def __init__(self, parent, text, command, bg_color, fg_color='white', **kwargs):
        super().__init__(parent, highlightthickness=0, **kwargs)
        self.command = command
        self.bg_color = bg_color
        self.hover_color = self._lighten_color(bg_color)
        self.fg_color = fg_color
        self.text = text
        self.is_hovered = False
        
        self.configure(bg=bg_color, width=kwargs.get('width', 200), height=kwargs.get('height', 50))
        self.bind('<Button-1>', self._on_click)
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        
        self._draw()
    
    def _lighten_color(self, hex_color):
        """Lighten a hex color"""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, r + 30)
        g = min(255, g + 30)
        b = min(255, b + 30)
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def _draw(self):
        self.delete('all')
        color = self.hover_color if self.is_hovered else self.bg_color
        self.configure(bg=color)
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()
        self.create_text(width//2, height//2, text=self.text, fill=self.fg_color, 
                        font=('Segoe UI', 11, 'bold'))
    
    def _on_click(self, event):
        if self.command:
            self.command()
    
    def _on_enter(self, event):
        self.is_hovered = True
        self._draw()
        self.configure(cursor='hand2')
    
    def _on_leave(self, event):
        self.is_hovered = False
        self._draw()
        self.configure(cursor='')


class EnhancedNetworkAnalyzerGUI:
    """Enhanced graphical user interface for network traffic analyzer"""
    
    # Color scheme
    COLORS = {
        'bg_dark': '#1a1a2e',
        'bg_card': '#16213e',
        'primary': '#667eea',
        'primary_dark': '#5568d3',
        'secondary': '#764ba2',
        'success': '#10b981',
        'warning': '#f59e0b',
        'danger': '#ef4444',
        'text_light': '#e0e0e0',
        'text_dark': '#a0a0a0',
        'border': '#2a2a4e'
    }
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer - Enhanced Forensic Tool")
        self.root.geometry("1200x850")
        
        # Center window on screen
        self._center_window()
        
        # Set minimum size
        self.root.minsize(1000, 700)
        
        self.analyzer = NetworkAnalyzer()
        self.pcap_file = None
        self.analysis_running = False
        
        # Configure root background
        self.root.configure(bg=self.COLORS['bg_dark'])
        
        # Configure ttk styling
        self._setup_styles()
        
        # Create widgets
        self._create_widgets()
        
        # Setup drag and drop if available
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self._on_drop)
        except:
            # TkinterDnD2 not available, skip drag-and-drop
            pass
    
    def _center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = 1200
        height = 850
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _setup_styles(self):
        """Setup ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure frame styles
        style.configure('Card.TFrame', background=self.COLORS['bg_card'], 
                       relief='flat', borderwidth=0)
        style.configure('Main.TFrame', background=self.COLORS['bg_dark'])
        
        # Configure label styles
        style.configure('Title.TLabel', background=self.COLORS['primary'],
                       foreground='white', font=('Segoe UI', 24, 'bold'))
        style.configure('CardTitle.TLabel', background=self.COLORS['bg_card'],
                       foreground=self.COLORS['text_light'], font=('Segoe UI', 12, 'bold'))
        style.configure('CardText.TLabel', background=self.COLORS['bg_card'],
                       foreground=self.COLORS['text_dark'], font=('Segoe UI', 10))
        
        # Configure entry styles
        style.configure('Modern.TEntry', fieldbackground='white',
                       foreground='black', borderwidth=1, relief='solid')
    
    def _create_widgets(self):
        """Create all GUI widgets"""
        
        # Header with gradient effect (simulated)
        header_frame = tk.Frame(self.root, bg=self.COLORS['primary'], height=100)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Title
        title_container = tk.Frame(header_frame, bg=self.COLORS['primary'])
        title_container.pack(expand=True)
        
        title_icon = tk.Label(title_container, text="🔍", bg=self.COLORS['primary'],
                             font=('Segoe UI', 32))
        title_icon.pack(side=tk.LEFT, padx=10)
        
        title_label = tk.Label(
            title_container,
            text="Network Traffic Analyzer",
            font=('Segoe UI', 26, 'bold'),
            bg=self.COLORS['primary'],
            fg='white'
        )
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = tk.Label(
            header_frame,
            text="Professional Digital Forensic Analysis Tool",
            font=('Segoe UI', 10),
            bg=self.COLORS['primary'],
            fg='#e0e0ff'
        )
        subtitle_label.pack(pady=(0, 10))
        
        # Main container with scrollbar
        main_container = tk.Frame(self.root, bg=self.COLORS['bg_dark'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Section 1: File Selection (with drag-and-drop zone)
        self._create_file_section(main_container)
        
        # Section 2: Case Information
        self._create_case_info_section(main_container)
        
        # Section 3: Action Buttons
        self._create_action_buttons(main_container)
        
        # Section 4: Progress Section
        self._create_progress_section(main_container)
        
        # Status Bar
        self._create_status_bar()
    
    def _create_card_frame(self, parent, title, icon=""):
        """Create a card-style frame with title"""
        card = tk.Frame(parent, bg=self.COLORS['bg_card'], relief='solid', 
                       borderwidth=1, highlightbackground=self.COLORS['border'],
                       highlightthickness=1)
        card.pack(fill=tk.X, pady=10)
        
        # Card header
        header = tk.Frame(card, bg=self.COLORS['bg_card'])
        header.pack(fill=tk.X, padx=20, pady=(15, 10))
        
        title_label = tk.Label(
            header,
            text=f"{icon} {title}" if icon else title,
            font=('Segoe UI', 13, 'bold'),
            bg=self.COLORS['bg_card'],
            fg=self.COLORS['text_light']
        )
        title_label.pack(side=tk.LEFT)
        
        # Card content frame
        content = tk.Frame(card, bg=self.COLORS['bg_card'])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))
        
        return content
    
    def _create_file_section(self, parent):
        """Create file selection section with drag-and-drop"""
        content = self._create_card_frame(parent, "Step 1: Evidence File Selection", "📁")
        
        # Drop zone frame
        drop_zone = tk.Frame(content, bg='#1e2a4a', relief='solid', borderwidth=2,
                            highlightbackground=self.COLORS['primary'], highlightthickness=2)
        drop_zone.pack(fill=tk.X, pady=10)
        
        # Try to enable drag and drop on the drop zone
        try:
            drop_zone.drop_target_register(DND_FILES)
            drop_zone.dnd_bind('<<Drop>>', self._on_drop)
        except:
            pass
        
        # Drop zone content
        drop_icon = tk.Label(drop_zone, text="📂", font=('Segoe UI', 48),
                           bg='#1e2a4a', fg=self.COLORS['primary'])
        drop_icon.pack(pady=(20, 10))
        
        drop_text = tk.Label(drop_zone, text="Drag & Drop PCAP file here",
                           font=('Segoe UI', 12, 'bold'), bg='#1e2a4a',
                           fg=self.COLORS['text_light'])
        drop_text.pack()
        
        drop_subtext = tk.Label(drop_zone, text="or click browse button below",
                              font=('Segoe UI', 9), bg='#1e2a4a',
                              fg=self.COLORS['text_dark'])
        drop_subtext.pack(pady=(0, 20))
        
        # File info display
        file_info_frame = tk.Frame(content, bg=self.COLORS['bg_card'])
        file_info_frame.pack(fill=tk.X, pady=10)
        
        self.file_label = tk.Label(
            file_info_frame,
            text="No file selected",
            bg=self.COLORS['bg_card'],
            fg=self.COLORS['text_dark'],
            font=('Segoe UI', 10)
        )
        self.file_label.pack(side=tk.LEFT, padx=5)
        
        # Browse button
        browse_btn = tk.Button(
            file_info_frame,
            text="📁 Browse Files",
            command=self._browse_file,
            bg=self.COLORS['primary'],
            fg='white',
            font=('Segoe UI', 10, 'bold'),
            padx=25,
            pady=8,
            cursor='hand2',
            relief='flat',
            activebackground=self.COLORS['primary_dark'],
            activeforeground='white'
        )
        browse_btn.pack(side=tk.RIGHT)
    
    def _create_case_info_section(self, parent):
        """Create case information input section"""
        content = self._create_card_frame(parent, "Step 2: Case Information", "📋")
        
        # Create grid for form fields
        form_frame = tk.Frame(content, bg=self.COLORS['bg_card'])
        form_frame.pack(fill=tk.X)
        
        # Analyst Name
        self._create_form_field(form_frame, "Analyst Name:", 0, required=True)
        self.analyst_entry = tk.Entry(form_frame, width=50, font=('Segoe UI', 10),
                                     relief='solid', borderwidth=1)
        self.analyst_entry.grid(row=0, column=1, pady=8, padx=10, sticky=tk.W)
        
        # Case ID
        self._create_form_field(form_frame, "Case ID (optional):", 1)
        self.case_id_entry = tk.Entry(form_frame, width=50, font=('Segoe UI', 10),
                                      relief='solid', borderwidth=1)
        self.case_id_entry.grid(row=1, column=1, pady=8, padx=10, sticky=tk.W)
        
        # Authorized By
        self._create_form_field(form_frame, "Authorized By:", 2)
        self.authorized_entry = tk.Entry(form_frame, width=50, font=('Segoe UI', 10),
                                        relief='solid', borderwidth=1)
        self.authorized_entry.grid(row=2, column=1, pady=8, padx=10, sticky=tk.W)
        
        # Description
        self._create_form_field(form_frame, "Case Description:", 3)
        self.description_text = tk.Text(form_frame, width=50, height=4,
                                       font=('Segoe UI', 9), relief='solid', borderwidth=1)
        self.description_text.grid(row=3, column=1, pady=8, padx=10, sticky=tk.W)
    
    def _create_form_field(self, parent, label_text, row, required=False):
        """Create a form field label"""
        label = tk.Label(
            parent,
            text=label_text + (" *" if required else ""),
            bg=self.COLORS['bg_card'],
            fg=self.COLORS['text_light'] if required else self.COLORS['text_dark'],
            font=('Segoe UI', 10, 'bold' if required else 'normal'),
            anchor=tk.W
        )
        label.grid(row=row, column=0, sticky=tk.W, pady=8, padx=(0, 10))
    
    def _create_action_buttons(self, parent):
        """Create action buttons section"""
        content = self._create_card_frame(parent, "Step 3: Execute Analysis", "▶️")
        
        button_frame = tk.Frame(content, bg=self.COLORS['bg_card'])
        button_frame.pack(pady=10)
        
        # Start Analysis Button
        self.analyze_btn = tk.Button(
            button_frame,
            text="▶ START FORENSIC ANALYSIS",
            command=self._start_analysis,
            bg=self.COLORS['success'],
            fg='white',
            font=('Segoe UI', 13, 'bold'),
            padx=50,
            pady=15,
            cursor='hand2',
            relief='flat',
            activebackground='#0d9668',
            activeforeground='white'
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear Form Button
        clear_btn = tk.Button(
            button_frame,
            text="🔄 Clear Form",
            command=self._clear_form,
            bg=self.COLORS['text_dark'],
            fg='white',
            font=('Segoe UI', 11, 'bold'),
            padx=30,
            pady=15,
            cursor='hand2',
            relief='flat',
            activebackground='#808080',
            activeforeground='white'
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
    
    def _create_progress_section(self, parent):
        """Create progress monitoring section"""
        content = self._create_card_frame(parent, "Analysis Progress", "📊")
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            content,
            variable=self.progress_var,
            maximum=100,
            length=400,
            mode='determinate'
        )
        self.progress_bar.pack(pady=(10, 5))
        
        # Progress percentage label
        self.progress_label = tk.Label(
            content,
            text="0%",
            bg=self.COLORS['bg_card'],
            fg=self.COLORS['text_light'],
            font=('Segoe UI', 10, 'bold')
        )
        self.progress_label.pack()
        
        # Progress text area
        progress_text_frame = tk.Frame(content, bg=self.COLORS['bg_card'])
        progress_text_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.progress_text = scrolledtext.ScrolledText(
            progress_text_frame,
            width=100,
            height=12,
            bg='#0d1117',
            fg='#c9d1d9',
            font=('Consolas', 9),
            relief='solid',
            borderwidth=1,
            insertbackground='white'
        )
        self.progress_text.pack(fill=tk.BOTH, expand=True)
        
        # Add color tags for different message types
        self.progress_text.tag_config('success', foreground='#3fb950')
        self.progress_text.tag_config('warning', foreground='#d29922')
        self.progress_text.tag_config('error', foreground='#f85149')
        self.progress_text.tag_config('info', foreground='#58a6ff')
        self.progress_text.tag_config('step', foreground='#bc8cff', font=('Consolas', 9, 'bold'))
    
    def _create_status_bar(self):
        """Create status bar at bottom"""
        self.status_bar = tk.Label(
            self.root,
            text="Ready to analyze",
            bg=self.COLORS['primary'],
            fg='white',
            anchor=tk.W,
            padx=15,
            font=('Segoe UI', 9),
            height=2
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _browse_file(self):
        """Browse for PCAP file"""
        filename = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[
                ("PCAP Files", "*.pcap *.pcapng"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            self._set_file(filename)
    
    def _on_drop(self, event):
        """Handle file drop event"""
        # Get the dropped file path
        files = self.root.tk.splitlist(event.data)
        if files:
            filename = files[0]
            # Validate file extension
            if filename.lower().endswith(('.pcap', '.pcapng')):
                self._set_file(filename)
            else:
                messagebox.showerror("Invalid File", 
                                   "Please drop a valid PCAP file (.pcap or .pcapng)")
    
    def _set_file(self, filename):
        """Set the selected file"""
        self.pcap_file = filename
        file_size = os.path.getsize(filename)
        size_str = self._format_file_size(file_size)
        
        self.file_label.config(
            text=f"✓ {os.path.basename(filename)} ({size_str})",
            fg=self.COLORS['success']
        )
        self._log_message(f"Selected file: {filename}", 'info')
    
    def _format_file_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _clear_form(self):
        """Clear all form fields"""
        if self.analysis_running:
            messagebox.showwarning("Analysis Running", 
                                 "Cannot clear form while analysis is running")
            return
        
        self.pcap_file = None
        self.file_label.config(text="No file selected", fg=self.COLORS['text_dark'])
        self.analyst_entry.delete(0, tk.END)
        self.case_id_entry.delete(0, tk.END)
        self.authorized_entry.delete(0, tk.END)
        self.description_text.delete(1.0, tk.END)
        self.progress_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self._log_message("Form cleared", 'info')
    
    def _start_analysis(self):
        """Start forensic analysis"""
        if self.analysis_running:
            messagebox.showwarning("Analysis Running", 
                                 "An analysis is already in progress")
            return
        
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
            "Start forensic analysis?\n\n"
            "This will process the PCAP file and generate comprehensive reports.\n"
            f"File: {os.path.basename(self.pcap_file)}"
        ):
            return
        
        # Clear previous progress
        self.progress_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        
        # Get inputs
        case_id = self.case_id_entry.get().strip() or None
        authorized_by = self.authorized_entry.get().strip() or None
        description = self.description_text.get(1.0, tk.END).strip()
        
        # Disable button
        self.analyze_btn.config(state='disabled', bg='#808080')
        self.analysis_running = True
        
        # Update status
        self.status_bar.config(text="⏳ Analysis in progress...", bg=self.COLORS['warning'])
        
        # Run analysis in separate thread
        thread = threading.Thread(
            target=self._run_analysis_thread,
            args=(analyst_name, case_id, authorized_by, description),
            daemon=True
        )
        thread.start()
    
    def _run_analysis_thread(self, analyst_name, case_id, authorized_by, description):
        """Run analysis in background thread"""
        try:
            # Redirect output to GUI
            old_stdout = sys.stdout
            sys.stdout = TextRedirector(self, self.root)
            
            # Run analysis
            self.analyzer.run_analysis(
                pcap_file=self.pcap_file,
                analyst_name=analyst_name,
                case_id=case_id,
                authorized_by=authorized_by,
                case_description=description
            )
            
            sys.stdout = old_stdout
            
            # Update progress to 100%
            self.root.after(0, lambda: self.progress_var.set(100))
            self.root.after(0, lambda: self.progress_label.config(text="100%"))
            
            # Show completion message
            self.root.after(0, lambda: self.status_bar.config(
                text="✓ Analysis complete!", bg=self.COLORS['success']))
            
            self.root.after(0, lambda: messagebox.showinfo(
                "Analysis Complete",
                f"Forensic analysis completed successfully!\n\n"
                f"Case ID: {self.analyzer.case_id}\n"
                f"Reports saved to: reports/{self.analyzer.case_id}/\n\n"
                "Check the progress window for detailed results."
            ))
            
        except Exception as e:
            self.root.after(0, lambda: self.status_bar.config(
                text="✗ Analysis failed", bg=self.COLORS['danger']))
            self.root.after(0, lambda: messagebox.showerror(
                "Error", f"Analysis failed:\n\n{str(e)}"))
            self.root.after(0, lambda: self._log_message(f"ERROR: {str(e)}", 'error'))
        
        finally:
            # Re-enable button
            self.root.after(0, lambda: self.analyze_btn.config(
                state='normal', bg=self.COLORS['success']))
            self.analysis_running = False
    
    def _log_message(self, message, tag='info'):
        """Log message to progress window with color coding"""
        self.progress_text.insert(tk.END, message + "\n", tag)
        self.progress_text.see(tk.END)
        
        # Update progress bar based on steps
        if '[STEP' in message:
            # Extract step number
            try:
                step_part = message.split('[STEP')[1].split(']')[0]
                current, total = map(int, step_part.split('/'))
                progress = (current / total) * 100
                self.progress_var.set(progress)
                self.progress_label.config(text=f"{progress:.0f}%")
            except:
                pass


class TextRedirector:
    """Redirects print output to Text widget with color coding"""
    
    def __init__(self, gui, root):
        self.gui = gui
        self.root = root
    
    def write(self, text):
        # Determine tag based on content
        tag = 'info'
        if '[+]' in text or '✓' in text or 'complete' in text.lower():
            tag = 'success'
        elif '[!]' in text or '⚠' in text or 'WARNING' in text:
            tag = 'warning'
        elif 'ERROR' in text or 'failed' in text.lower():
            tag = 'error'
        elif '[STEP' in text:
            tag = 'step'
        
        self.root.after(0, lambda: self.gui._log_message(text.rstrip(), tag))
    
    def flush(self):
        pass


def launch_gui():
    """Launch the enhanced GUI application"""
    # Try to use TkinterDnD for drag-and-drop
    try:
        root = TkinterDnD.Tk()
    except:
        # Fall back to regular Tk if TkinterDnD not available
        root = tk.Tk()
        print("Note: Install tkinterdnd2 for drag-and-drop support: pip install tkinterdnd2")
    
    app = EnhancedNetworkAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
