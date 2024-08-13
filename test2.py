import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import time
from fpdf import FPDF
import re
# Import the functions from each of your scripts
from clam import run_clamav_scan, parse_summary, directories
from mass import check_mass_encryption
from lynis_tool import run_lynis_scan
from test import assess_risk

class RansomwareAssessmentTool(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Ransomware Assessment Tool")
        self.geometry("800x600")

        self.configure(bg="lightblue")

        # Title Label
        title_label = tk.Label(self, text="Ransomware Assessment Tool", font=("Helvetica", 24, "bold"), bg="lightblue")
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
        self.risk_frame = tk.Frame(self, bg="lightblue")
        self.risk_frame.pack(pady=20)

    def start_scan(self):
        # Disable the Scan button and enable the progress bar
        self.scan_button.config(state=tk.DISABLED)
        self.progress_bar.start()

        # Start the scan process in a separate thread
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()

    def run_scan(self):
        # Redirecting output to the GUI
        def log_to_gui(text):
            self.output_area.config(state=tk.NORMAL)
            self.output_area.insert(tk.END, text + "\n")
            self.output_area.see(tk.END)
            self.output_area.config(state=tk.DISABLED)

        log_to_gui("Starting Ransomware Scan...")

        # Step 1: Run ClamAV scans
        infected_files = []  # List to hold paths of infected files
        for i, directory in enumerate(directories):
            log_to_gui(f"Scanning directory: {directory} ...")
            scan_output = run_clamav_scan(directory)
            summary = parse_summary(scan_output)
            for key, value in summary.items():
                log_to_gui(f"{key}: {value}")
            if int(summary['Infected Files']) > 0:
                # Collect infected files from scan output
                infected_files.extend(re.findall(r'^(.*?):\s*.*\s*FOUND', scan_output, re.MULTILINE))

        # Step 2: Check for mass encryption
        directory_to_scan = '/home/vethavarshini/Desktop'
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
        print(scan_output)
        log_to_gui(scan_output)

        # Step 4: Display Risk Assessment Questions in the GUI
        self.ask_risk_assessment(encrypted_files, infected_files)

        # Enable the Download button after the scan is complete
        self.progress_bar.stop()

    def ask_risk_assessment(self, encrypted_files, infected_files):
        # Clear the output area
        self.output_area.config(state=tk.NORMAL)
        self.output_area.delete("1.0", tk.END)
        self.output_area.config(state=tk.DISABLED)

        # Display questions in the risk assessment frame
        tk.Label(self.risk_frame, text="Do you have Antivirus software? (yes/no):", bg="lightblue").pack(anchor="w")
        antivirus_entry = tk.Entry(self.risk_frame, textvariable=self.antivirus_var)
        antivirus_entry.pack(anchor="w")

        tk.Label(self.risk_frame, text="When was your last backup done? (please enter in YYYY-MM-DD format):", bg="lightblue").pack(anchor="w")
        backup_date_entry = tk.Entry(self.risk_frame, textvariable=self.backup_date_var)
        backup_date_entry.pack(anchor="w")

        tk.Label(self.risk_frame, text="Have you ever faced any Ransomware attack before? (yes/no):", bg="lightblue").pack(anchor="w")
        ransomware_attack_entry = tk.Entry(self.risk_frame, textvariable=self.ransomware_attack_var)
        ransomware_attack_entry.pack(anchor="w")

        # Submit button to perform the risk assessment
        submit_button = tk.Button(self.risk_frame, text="Submit", command=lambda: self.perform_risk_assessment(encrypted_files, infected_files))
        submit_button.pack(pady=10)

    def perform_risk_assessment(self, encrypted_files, infected_files):
        antivirus = self.antivirus_var.get().strip().lower()
        last_backup = self.backup_date_var.get().strip()
        ransomware_attack = self.ransomware_attack_var.get().strip().lower()

    # Assess risk and display results in the output area
        risk_summary = assess_risk(antivirus, last_backup, ransomware_attack, encrypted_files, infected_files)
        if risk_summary:  # Check if the risk_summary is not None
            self.output_area.config(state=tk.NORMAL)
            self.output_area.insert(tk.END, "\nRansomware Risk Assessment Summary:\n")
            for line in risk_summary:
                self.output_area.insert(tk.END, line + "\n")
            self.output_area.see(tk.END)
            self.output_area.config(state=tk.DISABLED)

            # Enable the download button after displaying the summary
            self.download_button.config(state=tk.NORMAL)
        else:
            messagebox.showwarning("Warning", "Risk assessment returned no results.")


    def download_summary(self):
        # Generate and save the assessment summary as a PDF
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            # Adding a title
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, txt="Ransomware Assessment Summary", ln=True, align='C')

            # Adding the content
            self.output_area.config(state=tk.NORMAL)
            content = self.output_area.get("1.0", tk.END)
            self.output_area.config(state=tk.DISABLED)

            for line in content.splitlines():
                pdf.set_font("Arial", size=12)
                pdf.multi_cell(0, 10, line)

            pdf_file = "Ransomware_Assessment_Summary.pdf"
            pdf.output(pdf_file)
            messagebox.showinfo("Download Complete", f"Assessment Summary saved as {pdf_file}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving the PDF: {str(e)}")

if __name__ == "__main__":
    app = RansomwareAssessmentTool()
    app.mainloop()
