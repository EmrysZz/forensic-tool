"""
Analysis Dashboard - Interactive Single-Page Design
Clickable cards with detail popups, no scrolling needed
"""

import tkinter as tk
from tkinter import ttk, messagebox
import os
import webbrowser
import subprocess


class AnalysisDashboard:
    """Interactive dashboard with clickable cards"""
    
    def __init__(self, parent, analyzer):
        """Initialize dashboard"""
        self.parent = parent
        self.analyzer = analyzer
        self.window = tk.Toplevel(parent)
        self.window.title(f"Analysis Dashboard - {analyzer.case_id}")
        self.window.geometry("1200x700")
        self.window.resizable(False, False)  # Fixed size, no scrolling needed
        
        # Modern color scheme
        self.colors = {
            'primary': '#2563eb',
            'success': '#10b981',
            'warning': '#f59e0b',
            'danger': '#ef4444',
            'purple': '#8b5cf6',
            'bg_light': '#f8fafc',
            'bg_card': '#ffffff',
            'text_dark': '#1e293b',
            'text_light': '#64748b',
            'border': '#e2e8f0'
        }
        
        # Center window
        self._center_window()
        
        # Make modal
        self.window.transient(parent)
        self.window.grab_set()
        
        # Configure window
        self.window.configure(bg=self.colors['bg_light'])
        
        # Create widgets
        self._create_widgets()
    
    def _center_window(self):
        """Center window on screen"""
        self.window.update_idletasks()
        width = 1200
        height = 700
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
    
    def _create_widgets(self):
        """Create dashboard widgets - single page, no scrolling"""
        
        # Header
        header_frame = tk.Frame(self.window, bg=self.colors['primary'], height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        header_content = tk.Frame(header_frame, bg=self.colors['primary'])
        header_content.pack(expand=True, fill=tk.BOTH, padx=30)
        
        title_label = tk.Label(
            header_content,
            text="✓ Analysis Complete",
            font=('Segoe UI', 22, 'bold'),
            bg=self.colors['primary'],
            fg='white'
        )
        title_label.pack(side=tk.LEFT, pady=15)
        
        case_label = tk.Label(
            header_content,
            text=f"Case: {self.analyzer.case_id}",
            font=('Segoe UI', 11),
            bg=self.colors['primary'],
            fg='white'
        )
        case_label.pack(side=tk.RIGHT, pady=15)
        
        # Main content - NO SCROLLING
        main_frame = tk.Frame(self.window, bg=self.colors['bg_light'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Top row: Statistics cards (clickable)
        self._create_stats_row(main_frame)
        
        # Middle row: Summary and Threats side by side
        middle_frame = tk.Frame(main_frame, bg=self.colors['bg_light'])
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Left: Executive Summary (clickable)
        self._create_summary_card(middle_frame)
        
        # Right: Suspicious Activity (clickable)
        self._create_threats_card(middle_frame)
        
        # Bottom row: Report buttons
        self._create_reports_row(main_frame)
        
        # Bottom bar
        self._create_bottom_bar()
    
    def _create_stats_row(self, parent):
        """Create statistics cards row - all clickable"""
        stats_frame = tk.Frame(parent, bg=self.colors['bg_light'])
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        results = self.analyzer.analysis_results
        
        # Get data
        total_packets = results.get('total_packets', 0)
        ip_comms = results.get('ip_communications', {})
        src_ips = ip_comms.get('unique_source_ips', 0)
        dst_ips = ip_comms.get('unique_destination_ips', 0)
        
        suspicious = results.get('suspicious_activity', {})
        total_threats = sum([
            len(suspicious.get('port_scans', [])),
            len(suspicious.get('syn_floods', [])),
            len(suspicious.get('udp_floods', [])),
            len(suspicious.get('icmp_floods', [])),
            len(suspicious.get('ddos_indicators', [])),
            len(suspicious.get('high_volume_ips', [])),
            len(suspicious.get('malicious_transfers', []))
        ])
        
        # Create cards
        self._create_stat_card(stats_frame, "📦 Total Packets", f"{total_packets:,}", 
                              self.colors['primary'], 0, self._show_packets_detail)
        self._create_stat_card(stats_frame, "🌐 Source IPs", str(src_ips),
                              self.colors['success'], 1, self._show_source_ips_detail)
        self._create_stat_card(stats_frame, "🎯 Destination IPs", str(dst_ips),
                              self.colors['purple'], 2, self._show_dest_ips_detail)
        
        threat_color = self.colors['danger'] if total_threats > 0 else self.colors['success']
        self._create_stat_card(stats_frame, "⚠️ Threats", str(total_threats),
                              threat_color, 3, self._show_threats_detail)
    
    def _create_stat_card(self, parent, title, value, color, column, click_command):
        """Create clickable statistics card"""
        card = tk.Frame(parent, bg=self.colors['bg_card'], relief='flat',
                       highlightbackground=self.colors['border'], highlightthickness=1,
                       cursor='hand2')
        card.grid(row=0, column=column, padx=6, sticky='ew')
        parent.grid_columnconfigure(column, weight=1)
        
        # Color accent
        accent = tk.Frame(card, bg=color, height=4)
        accent.pack(fill=tk.X)
        
        # Content
        content = tk.Frame(card, bg=self.colors['bg_card'])
        content.pack(fill=tk.BOTH, expand=True, padx=15, pady=12)
        
        title_label = tk.Label(content, text=title, font=('Segoe UI', 9),
                              bg=self.colors['bg_card'], fg=self.colors['text_light'])
        title_label.pack(anchor=tk.W)
        
        value_label = tk.Label(content, text=value, font=('Segoe UI', 24, 'bold'),
                              bg=self.colors['bg_card'], fg=self.colors['text_dark'])
        value_label.pack(anchor=tk.W, pady=(3, 0))
        
        click_hint = tk.Label(content, text="Click for details →", font=('Segoe UI', 8),
                             bg=self.colors['bg_card'], fg=color)
        click_hint.pack(anchor=tk.W, pady=(3, 0))
        
        # Hover and click effects
        def on_enter(e):
            card.configure(highlightbackground=color, highlightthickness=2)
            click_hint.configure(font=('Segoe UI', 8, 'bold'))
        
        def on_leave(e):
            card.configure(highlightbackground=self.colors['border'], highlightthickness=1)
            click_hint.configure(font=('Segoe UI', 8))
        
        def on_click(e):
            click_command()
        
        # Bind to all widgets in card
        for widget in [card, accent, content, title_label, value_label, click_hint]:
            widget.bind('<Enter>', on_enter)
            widget.bind('<Leave>', on_leave)
            widget.bind('<Button-1>', on_click)
    
    def _create_summary_card(self, parent):
        """Create executive summary card (clickable)"""
        card = tk.Frame(parent, bg=self.colors['bg_card'], relief='flat',
                       highlightbackground=self.colors['border'], highlightthickness=1,
                       cursor='hand2')
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Header
        header = tk.Frame(card, bg=self.colors['bg_card'])
        header.pack(fill=tk.X, padx=15, pady=12)
        
        title = tk.Label(header, text="📝 Executive Summary", font=('Segoe UI', 12, 'bold'),
                        bg=self.colors['bg_card'], fg=self.colors['text_dark'])
        title.pack(side=tk.LEFT)
        
        hint = tk.Label(header, text="Click to expand", font=('Segoe UI', 8),
                       bg=self.colors['bg_card'], fg=self.colors['primary'])
        hint.pack(side=tk.RIGHT)
        
        # Summary preview
        summary = self.analyzer._generate_executive_summary() if hasattr(self.analyzer, '_generate_executive_summary') else "Analysis completed."
        preview = summary[:200] + "..." if len(summary) > 200 else summary
        
        text_label = tk.Label(card, text=preview, font=('Segoe UI', 9),
                             bg=self.colors['bg_card'], fg=self.colors['text_dark'],
                             wraplength=520, justify=tk.LEFT)
        text_label.pack(padx=15, pady=(0, 12), anchor=tk.W)
        
        # Click binding
        def on_click(e):
            self._show_summary_detail()
        
        def on_enter(e):
            card.configure(highlightbackground=self.colors['primary'], highlightthickness=2)
            hint.configure(font=('Segoe UI', 8, 'bold'))
        
        def on_leave(e):
            card.configure(highlightbackground=self.colors['border'], highlightthickness=1)
            hint.configure(font=('Segoe UI', 8))
        
        for widget in [card, header, title, hint, text_label]:
            widget.bind('<Button-1>', on_click)
            widget.bind('<Enter>', on_enter)
            widget.bind('<Leave>', on_leave)
    
    def _create_threats_card(self, parent):
        """Create threats card (clickable)"""
        suspicious = self.analyzer.analysis_results.get('suspicious_activity', {})
        
        threats = {
            'DDoS': len(suspicious.get('ddos_indicators', [])),
            'SYN Floods': len(suspicious.get('syn_floods', [])),
            'UDP Floods': len(suspicious.get('udp_floods', [])),
            'Port Scans': len(suspicious.get('port_scans', [])),
        }
        
        total = sum(threats.values())
        color = self.colors['warning'] if total > 0 else self.colors['success']
        
        card = tk.Frame(parent, bg=self.colors['bg_card'], relief='flat',
                       highlightbackground=self.colors['border'], highlightthickness=1,
                       cursor='hand2')
        card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Accent bar
        accent = tk.Frame(card, bg=color, height=4)
        accent.pack(fill=tk.X)
        
        # Header
        header = tk.Frame(card, bg=self.colors['bg_card'])
        header.pack(fill=tk.X, padx=15, pady=12)
        
        icon = "⚠️" if total > 0 else "✓"
        title_text = f"{icon} Suspicious Activity" if total > 0 else f"{icon} No Threats Detected"
        title = tk.Label(header, text=title_text, font=('Segoe UI', 12, 'bold'),
                        bg=self.colors['bg_card'], fg=self.colors['text_dark'])
        title.pack(side=tk.LEFT)
        
        hint = tk.Label(header, text="Click for details", font=('Segoe UI', 8),
                       bg=self.colors['bg_card'], fg=color)
        hint.pack(side=tk.RIGHT)
        
        # Threat summary
        if total > 0:
            summary_frame = tk.Frame(card, bg=self.colors['bg_card'])
            summary_frame.pack(fill=tk.X, padx=15, pady=(0, 12))
            
            for threat_type, count in threats.items():
                if count > 0:
                    row = tk.Frame(summary_frame, bg=self.colors['bg_card'])
                    row.pack(fill=tk.X, pady=2)
                    
                    tk.Label(row, text=threat_type, font=('Segoe UI', 9),
                            bg=self.colors['bg_card'], fg=self.colors['text_light']).pack(side=tk.LEFT)
                    tk.Label(row, text=str(count), font=('Segoe UI', 9, 'bold'),
                            bg=self.colors['bg_card'], fg=self.colors['danger']).pack(side=tk.RIGHT)
        else:
            msg = tk.Label(card, text="No suspicious activity detected", font=('Segoe UI', 9),
                          bg=self.colors['bg_card'], fg=self.colors['text_light'])
            msg.pack(padx=15, pady=(0, 12))
        
        # Click binding
        def on_click(e):
            self._show_threats_detail()
        
        def on_enter(e):
            card.configure(highlightbackground=color, highlightthickness=2)
            hint.configure(font=('Segoe UI', 8, 'bold'))
        
        def on_leave(e):
            card.configure(highlightbackground=self.colors['border'], highlightthickness=1)
            hint.configure(font=('Segoe UI', 8))
        
        card.bind('<Button-1>', on_click)
        card.bind('<Enter>', on_enter)
        card.bind('<Leave>', on_leave)
        accent.bind('<Button-1>', on_click)
        header.bind('<Button-1>', on_click)
        title.bind('<Button-1>', on_click)
        hint.bind('<Button-1>', on_click)
    
    def _create_reports_row(self, parent):
        """Create report buttons row"""
        reports_frame = tk.Frame(parent, bg=self.colors['bg_light'])
        reports_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Title
        title_frame = tk.Frame(reports_frame, bg=self.colors['bg_light'])
        title_frame.pack(fill=tk.X, pady=(0, 8))
        
        tk.Label(title_frame, text="📄 Forensic Reports", font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'], fg=self.colors['text_dark']).pack(side=tk.LEFT)
        
        # Buttons
        buttons_frame = tk.Frame(reports_frame, bg=self.colors['bg_light'])
        buttons_frame.pack(fill=tk.X)
        
        reports = [
            ("📊 HTML Report", self.colors['primary'], self._open_html),
            ("📑 PDF Report", self.colors['danger'], self._open_pdf),
            ("💾 JSON Data", '#6b7280', self._open_json),
            ("📁 Open Folder", self.colors['success'], self._open_folder)
        ]
        
        for idx, (text, color, command) in enumerate(reports):
            self._create_report_button(buttons_frame, text, color, command, idx)
    
    def _create_report_button(self, parent, text, color, command, column):
        """Create report button"""
        btn = tk.Button(parent, text=text, command=command, bg=color, fg='white',
                       font=('Segoe UI', 10, 'bold'), relief='flat', cursor='hand2',
                       padx=15, pady=10, borderwidth=0)
        btn.grid(row=0, column=column, padx=4, sticky='ew')
        parent.grid_columnconfigure(column, weight=1)
        
        def on_enter(e):
            btn.configure(bg=self._darken_color(color))
        
        def on_leave(e):
            btn.configure(bg=color)
        
        btn.bind('<Enter>', on_enter)
        btn.bind('<Leave>', on_leave)
    
    def _darken_color(self, hex_color):
        """Darken hex color"""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r, g, b = max(0, int(r * 0.85)), max(0, int(g * 0.85)), max(0, int(b * 0.85))
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def _create_bottom_bar(self):
        """Create bottom bar"""
        bottom = tk.Frame(self.window, bg='white', height=60)
        bottom.pack(side=tk.BOTTOM, fill=tk.X)
        bottom.pack_propagate(False)
        
        border = tk.Frame(bottom, bg=self.colors['border'], height=1)
        border.pack(fill=tk.X)
        
        btn_container = tk.Frame(bottom, bg='white')
        btn_container.pack(expand=True, fill=tk.BOTH, padx=20)
        
        close_btn = tk.Button(btn_container, text="Close Dashboard", command=self.window.destroy,
                             bg=self.colors['text_light'], fg='white', font=('Segoe UI', 10, 'bold'),
                             padx=25, pady=8, cursor='hand2', relief='flat', borderwidth=0)
        close_btn.pack(side=tk.RIGHT)
        
        def on_enter(e):
            close_btn.configure(bg=self.colors['text_dark'])
        
        def on_leave(e):
            close_btn.configure(bg=self.colors['text_light'])
        
        close_btn.bind('<Enter>', on_enter)
        close_btn.bind('<Leave>', on_leave)
    
    # Detail popup methods
    def _show_packets_detail(self):
        """Show packet details popup"""
        results = self.analyzer.analysis_results
        protocols = results.get('protocol_distribution', {})
        
        detail = "Packet Analysis Details\n" + "="*50 + "\n\n"
        detail += f"Total Packets: {results.get('total_packets', 0):,}\n\n"
        detail += "Protocol Distribution:\n"
        for proto, data in protocols.items():
            count = data.get('count', 0)
            pct = data.get('percentage', 0)
            detail += f"  • {proto}: {count:,} packets ({pct:.1f}%)\n"
        
        self._show_detail_popup("📦 Packet Details", detail)
    
    def _show_source_ips_detail(self):
        """Show source IPs details"""
        ip_comms = self.analyzer.analysis_results.get('ip_communications', {})
        top_ips = ip_comms.get('top_source_ips', {})
        
        detail = "Source IP Analysis\n" + "="*50 + "\n\n"
        detail += f"Unique Source IPs: {ip_comms.get('unique_source_ips', 0)}\n\n"
        detail += "Top Source IPs:\n"
        for ip, count in list(top_ips.items())[:10]:
            detail += f"  • {ip}: {count:,} packets\n"
        
        self._show_detail_popup("🌐 Source IPs", detail)
    
    def _show_dest_ips_detail(self):
        """Show destination IPs details"""
        ip_comms = self.analyzer.analysis_results.get('ip_communications', {})
        top_ips = ip_comms.get('top_destination_ips', {})
        
        detail = "Destination IP Analysis\n" + "="*50 + "\n\n"
        detail += f"Unique Destination IPs: {ip_comms.get('unique_destination_ips', 0)}\n\n"
        detail += "Top Destination IPs:\n"
        for ip, count in list(top_ips.items())[:10]:
            detail += f"  • {ip}: {count:,} packets\n"
        
        self._show_detail_popup("🎯 Destination IPs", detail)
    
    def _show_threats_detail(self):
        """Show threats details"""
        suspicious = self.analyzer.analysis_results.get('suspicious_activity', {})
        
        detail = "Threat Analysis Details\n" + "="*50 + "\n\n"
        
        for threat_type, key in [
            ("DDoS Indicators", 'ddos_indicators'),
            ("SYN Floods", 'syn_floods'),
            ("UDP Floods", 'udp_floods'),
            ("ICMP Floods", 'icmp_floods'),
            ("Port Scans", 'port_scans'),
            ("High Volume IPs", 'high_volume_ips'),
            ("Suspicious Transfers", 'malicious_transfers')
        ]:
            items = suspicious.get(key, [])
            if items:
                detail += f"\n{threat_type} ({len(items)}):\n"
                for item in items[:5]:  # Show first 5
                    if isinstance(item, dict):
                        detail += f"  • {item.get('source_ip', 'N/A')} - Severity: {item.get('severity', 'N/A')}\n"
                if len(items) > 5:
                    detail += f"  ... and {len(items) - 5} more\n"
        
        if not any(suspicious.values()):
            detail += "No threats detected. Network traffic appears normal."
        
        self._show_detail_popup("⚠️ Threat Details", detail)
    
    def _show_summary_detail(self):
        """Show full executive summary"""
        summary = self.analyzer._generate_executive_summary() if hasattr(self.analyzer, '_generate_executive_summary') else "Analysis completed successfully."
        self._show_detail_popup("📝 Executive Summary", summary)
    
    def _show_detail_popup(self, title, content):
        """Show detail popup window"""
        popup = tk.Toplevel(self.window)
        popup.title(title)
        popup.geometry("600x500")
        popup.transient(self.window)
        popup.grab_set()
        
        # Center popup
        popup.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - 300
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - 250
        popup.geometry(f"600x500+{x}+{y}")
        
        # Header
        header = tk.Frame(popup, bg=self.colors['primary'], height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        tk.Label(header, text=title, font=('Segoe UI', 16, 'bold'),
                bg=self.colors['primary'], fg='white').pack(pady=15)
        
        # Content
        text_frame = tk.Frame(popup, bg='white')
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        text = tk.Text(text_frame, wrap=tk.WORD, font=('Segoe UI', 10),
                      bg=self.colors['bg_light'], relief='flat', padx=15, pady=15)
        scrollbar = ttk.Scrollbar(text_frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text.insert(1.0, content)
        text.config(state='disabled')
        
        # Close button
        btn_frame = tk.Frame(popup, bg='white')
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        close_btn = tk.Button(btn_frame, text="Close", command=popup.destroy,
                             bg=self.colors['primary'], fg='white', font=('Segoe UI', 10, 'bold'),
                             padx=30, pady=8, cursor='hand2', relief='flat')
        close_btn.pack(side=tk.RIGHT)
    
    # Report methods
    def _open_html(self):
        """Open HTML report"""
        try:
            # Clean case_id and construct path properly
            case_id = str(self.analyzer.case_id).strip()
            report_dir = os.path.join("reports", case_id)
            html_file = os.path.join(report_dir, f"report_{case_id}.html")
            
            print(f"DEBUG: Looking for HTML at: {html_file}")  # Debug
            
            if os.path.exists(html_file):
                webbrowser.open(f'file://{os.path.abspath(html_file)}')
            else:
                messagebox.showerror("Error", f"HTML report not found:\n{html_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open HTML report:\n{str(e)}")
    
    def _open_pdf(self):
        """Open PDF report"""
        try:
            # Clean case_id and construct path properly
            case_id = str(self.analyzer.case_id).strip()
            report_dir = os.path.join("reports", case_id)
            pdf_file = os.path.join(report_dir, f"report_{case_id}.pdf")
            
            print(f"DEBUG: Looking for PDF at: {pdf_file}")  # Debug
            
            if os.path.exists(pdf_file):
                os.startfile(os.path.abspath(pdf_file))
            else:
                messagebox.showerror("Error", f"PDF report not found:\n{pdf_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open PDF report:\n{str(e)}")
    
    def _open_json(self):
        """Open JSON data"""
        try:
            # Clean case_id and construct path properly
            case_id = str(self.analyzer.case_id).strip()
            report_dir = os.path.join("reports", case_id)
            json_file = os.path.join(report_dir, f"report_{case_id}.json")
            
            print(f"DEBUG: Looking for JSON at: {json_file}")  # Debug
            
            if os.path.exists(json_file):
                subprocess.run(['explorer', '/select,', os.path.abspath(json_file)])
            else:
                messagebox.showerror("Error", f"JSON data not found:\n{json_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to locate JSON data:\n{str(e)}")
    
    def _open_folder(self):
        """Open reports folder"""
        try:
            # Clean case_id and construct path properly
            case_id = str(self.analyzer.case_id).strip()
            report_dir = os.path.join("reports", case_id)
            
            print(f"DEBUG: Looking for directory at: {report_dir}")  # Debug
            
            if os.path.exists(report_dir):
                os.startfile(os.path.abspath(report_dir))
            else:
                messagebox.showerror("Error", f"Reports directory not found:\n{report_dir}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open directory:\n{str(e)}")


def show_dashboard(parent, analyzer):
    """Show analysis dashboard"""
    dashboard = AnalysisDashboard(parent, analyzer)
    return dashboard
