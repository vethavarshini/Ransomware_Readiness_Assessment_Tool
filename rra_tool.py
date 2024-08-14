import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
from fpdf import FPDF
import re

# Import the functions from each of your scripts
from clamscan import run_clamav_scan, parse_summary, directories
from mass_encrypt import check_mass_encryption
from lynis_scan import run_lynis_scan
from rra_CLI import assess_risk

class RansomwareAssessmentTool(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Ransomware Assessment Tool")
        self.geometry("800x600")
        self.configure(bg="gray")

        # Title Label
        title_label = tk.Label(self, text="Ransomware Assessment Tool", font=("Helvetica", 24, "bold"), bg="gray")
        title_label.pack(pady=20)

        # Scan Button
        self.scan_button = tk.Button(self, text="SCAN FOR RANSOMWARE", font=("Helvetica", 16, "bold"), command=self.start_scan, bg="red", fg="black")
        self.scan_button.pack(pady=20)

        # Progress Bar
        self.progress_bar = ttk.Progressbar(self, mode='indeterminate')
        self.progress_bar.pack(pady=20, fill=tk.X, padx=50)

        # Output Area
        self.output_area = ScrolledText(self, height=15, font=("Courier", 10))
        self.output_area.pack(pady=10, fill=tk.BOTH, padx=20, expand=True)
        self.output_area.config(state=tk.DISABLED)

        # Download Button (Initially disabled)
        self.download_button = tk.Button(self, text="Download Assessment Summary", font=("Helvetica", 14), state=tk.DISABLED, command=self.download_summary, bg="green", fg="white")
        self.download_button.pack(pady=20)

        # Risk Assessment Variables
        self.antivirus_var = tk.StringVar()
        self.backup_date_var = tk.StringVar()
        self.ransomware_attack_var = tk.StringVar()

        # Risk Assessment Frame (Initially hidden)
        self.risk_frame = tk.Frame(self, bg="gray")
        self.risk_frame.pack_forget()  # Hide initially

        # Initialize summary variables
        self.risk_summary = []
        self.lynis_summary = []

    def start_scan(self):
        self.scan_button.config(state=tk.DISABLED)
        self.progress_bar.start()

        # Start the scan process in a separate thread
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()

    def run_scan(self):
        def log_to_gui(text):
            self.output_area.config(state=tk.NORMAL)
            self.output_area.insert(tk.END, text + "\n")
            self.output_area.see(tk.END)
            self.output_area.config(state=tk.DISABLED)

        log_to_gui("Starting Ransomware Scan...")

        # Step 1: Run ClamAV scans
        infected_files = []
        for i, directory in enumerate(directories):
            log_to_gui(f"Scanning directory: {directory} ...")
            scan_output = run_clamav_scan(directory)
            summary = parse_summary(scan_output)
            for key, value in summary.items():
                log_to_gui(f"{key}: {value}")
            if int(summary['Infected Files']) > 0:
                infected_files.extend(re.findall(r'^(.*?):\s*.*\s*FOUND', scan_output, re.MULTILINE))

        # Step 2: Check for mass encryption
        directory_to_scan = '/home/<username>/Desktop' #Add your path to scan
        scan_depth = 5
        log_to_gui("\nChecking for mass encryption...")
        encrypted_files = check_mass_encryption(directory=directory_to_scan, scan_depth=scan_depth)
        if encrypted_files:
            log_to_gui("Suspicious encrypted files detected:")
            log_to_gui("╒══════════════════════════════════════════════════════════╕")
            log_to_gui("│ File Path                                                │")
            log_to_gui("╞══════════════════════════════════════════════════════════╡")
            for file in encrypted_files:
                log_to_gui(f"│ {file.ljust(55)}│")
                log_to_gui("├──────────────────────────────────────────────────────────┤")
            log_to_gui("╘══════════════════════════════════════════════════════════╛")
            log_to_gui(f"\nTotal suspicious encrypted files found: {len(encrypted_files)}")

        # Step 3: Run Lynis system scan
        log_to_gui("\nRunning System Scan with Lynis...")
        scan_output = run_lynis_scan()

        # Remove any terminal color codes from Lynis output
        clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', scan_output)

        # Extract only the required information from Lynis scan output
        self.lynis_summary = []  # Store Lynis summary as an instance variable
        capturing = False
        for line in clean_output.splitlines():
            if any(keyword in line for keyword in ["[+] Networking", "[+] Software: firewalls", "[+] Software: file integrity", "[+] Software: Malware"]):
                capturing = True
            if capturing and not any(skip_keyword in line for skip_keyword in [
                "[+] Plugins", "[+] Printers and Spools", "[+] Software: e-mail and messaging", 
                "[+] Software: webserver", "[+] SSH Support", "[+] SNMP Support", "[+] Databases",
                "[+] LDAP Services", "[+] PHP", "[+] Logging and files", "[+] Insecure services", 
                "[+] Banners and identification", "-[ Lynis", "Warnings ("]):
                self.lynis_summary.append(line)
            if "Components:" in line:
                self.lynis_summary.append(line)
                capturing = True
            if "  - Firewall" in line or "  - Malware scanner" in line:
                self.lynis_summary.append(line)

        log_to_gui("\n".join(self.lynis_summary))

        # Step 4: Display Risk Assessment Questions in the GUI
        self.ask_risk_assessment(encrypted_files, infected_files)

        # Stop progress bar
        self.progress_bar.stop()

    def ask_risk_assessment(self, encrypted_files, infected_files):
        # Display questions in the risk assessment frame
        self.risk_frame.pack(pady=20)  # Show the risk frame

        # Clear existing widgets in risk_frame
        for widget in self.risk_frame.winfo_children():
            widget.destroy()

        # Display questions in the risk assessment frame
        tk.Label(self.risk_frame, text="Do you have Antivirus software? (yes/no):", bg="gray").pack(anchor="w")
        antivirus_entry = tk.Entry(self.risk_frame, textvariable=self.antivirus_var)
        antivirus_entry.pack(anchor="w")

        tk.Label(self.risk_frame, text="When was your last backup done? (please enter in YYYY-MM-DD format):", bg="gray").pack(anchor="w")
        backup_date_entry = tk.Entry(self.risk_frame, textvariable=self.backup_date_var)
        backup_date_entry.pack(anchor="w")

        tk.Label(self.risk_frame, text="Have you ever faced any Ransomware attack before? (yes/no):", bg="gray").pack(anchor="w")
        ransomware_attack_entry = tk.Entry(self.risk_frame, textvariable=self.ransomware_attack_var)
        ransomware_attack_entry.pack(anchor="w")

        # Submit button to perform the risk assessment
        submit_button = tk.Button(self.risk_frame, text="Submit", command=lambda: self.perform_risk_assessment(encrypted_files, infected_files))
        submit_button.pack(pady=10)

    def perform_risk_assessment(self, encrypted_files, infected_files):
        antivirus = self.antivirus_var.get().strip().lower()
        last_backup = self.backup_date_var.get().strip()
        ransomware_attack = self.ransomware_attack_var.get().strip().lower()

        self.risk_summary = assess_risk(antivirus, last_backup, ransomware_attack, encrypted_files, infected_files)
        if self.risk_summary:
            self.output_area.config(state=tk.NORMAL)
            self.output_area.insert(tk.END, "\nRansomware Risk Assessment Summary:\n")
            for line in self.risk_summary:
                self.output_area.insert(tk.END, line + "\n")
            self.output_area.see(tk.END)
            self.output_area.config(state=tk.DISABLED)

            # Enable the download button after displaying the summary
            self.download_button.config(state=tk.NORMAL)
        else:
            messagebox.showwarning("Warning", "Risk assessment returned no results.")

    def download_summary(self):
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            # Adding a title
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, txt="Ransomware Assessment Summary", ln=True, align='C')

            # Add Risk Assessment Summary
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(200, 10, txt="Risk Assessment Summary:", ln=True, align='L')
            pdf.set_font("Arial", size=12)
            for line in self.risk_summary:
                pdf.multi_cell(0, 10, line)

            # Add Lynis System Information
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(200, 10, txt="Lynis System Information:", ln=True, align='L')
            pdf.set_font("Arial", size=12)
            for line in self.lynis_summary:
                formatted_line = line.ljust(100)  # Adjust the number to control the alignment width
                pdf.multi_cell(0, 10, formatted_line)

            pdf_file = "Ransomware_Assessment_Summary.pdf"
            pdf.output(pdf_file)
            messagebox.showinfo("Success", f"Summary saved as {pdf_file}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PDF: {str(e)}")


if __name__ == "__main__":
    app = RansomwareAssessmentTool()
    app.mainloop()
