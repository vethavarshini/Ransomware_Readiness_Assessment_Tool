import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import re
from fpdf import FPDF

# Import the functions from each of your scripts
from clam import run_clamav_scan, parse_summary, directories, directories_names
from mass import check_mass_encryption
from lynis_tool import run_lynis_scan
from test import assess_risk, get_user_inputs

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
        self.scan_button = tk.Button(self, text="SCAN FOR RANSOMWARE", font=("Helvetica", 16, "bold"), command=self.start_scan, bg="red", fg="white")
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
        
        # Display the mass encryption results
        if encrypted_files:
            log_to_gui("Suspicious encrypted files detected:")
            for file in encrypted_files:
                log_to_gui(f"  - {file}")
            log_to_gui(f"\nTotal suspicious encrypted files found: {len(encrypted_files)}")
        else:
            log_to_gui("No suspicious encrypted files found.")

        # Step 3: Run Lynis system scan
        log_to_gui("\nRunning System Scan with Lynis...")
        scan_output = run_lynis_scan()
        log_to_gui(scan_output)

        # Step 4: User input and risk assessment
        log_to_gui("\nPerforming Risk Assessment...")
        antivirus, last_backup, ransomware_attack = get_user_inputs()
        risk_summary = assess_risk(antivirus, last_backup, ransomware_attack, encrypted_files, infected_files)
        
        # Display the risk assessment summary in the GUI
        log_to_gui("\nRansomware Risk Assessment Summary:")
        for line in risk_summary:
            log_to_gui(line)

        # Enable the Download button after the scan is complete
        self.progress_bar.stop()
        self.download_button.config(state=tk.NORMAL)

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
