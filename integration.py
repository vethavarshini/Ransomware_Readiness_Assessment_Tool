# # main_ransomware_detection_pdf.py

# import subprocess
# import re
# from rich.console import Console
# from rich.table import Table
# from pyfiglet import figlet_format
# from termcolor import colored
# from tabulate import tabulate
# import os
# from datetime import datetime
# from fpdf import FPDF

# # Import the functions from each of your scripts
# from clam import run_clamav_scan, parse_summary, display_summary, directories, directories_names
# from mass import check_mass_encryption
# from lynis_tool import run_lynis_scan

# class PDFReport(FPDF):
#     def header(self):
#         self.set_font('Arial', 'B', 12)
#         self.cell(0, 10, 'Ransomware Detection Report', 0, 1, 'C')
#         self.ln(10)

#     def chapter_title(self, title):
#         self.set_font('Arial', 'B', 12)
#         self.cell(0, 10, title, 0, 1, 'L')
#         self.ln(5)

#     def chapter_body(self, body):
#         self.set_font('Arial', '', 12)
#         self.multi_cell(0, 10, body)
#         self.ln()

#     def add_chapter(self, title, body):
#         self.add_page()
#         self.chapter_title(title)
#         self.chapter_body(body)

# def run_clamav_and_generate_output():
#     output = ""
#     for i, directory in enumerate(directories):
#         scan_output = run_clamav_scan(directory)
#         summary = parse_summary(scan_output)
        
#         output += f"ClamAV Scan Results for {directories_names[i]}:\n"
#         for key, value in summary.items():
#             output += f"{key}: {value}\n"
#         output += "\n"
    
#     return output

# def run_mass_encryption_and_generate_output():
#     directory_to_scan = '/home/vethavarshini/Downloads'
#     scan_depth = 5
#     encrypted_files = check_mass_encryption(directory=directory_to_scan, scan_depth=scan_depth)

#     if encrypted_files:
#         output = "Suspicious encrypted files detected:\n"
#         output += tabulate([[file] for file in encrypted_files], headers=["File Path"], tablefmt="grid")
#     else:
#         output = "No suspicious encrypted files found."

#     return output

# def run_lynis_and_generate_output():
#     scan_output = run_lynis_scan()
#     return scan_output

# def main():
#     # Initialize PDF
#     pdf = PDFReport()

#     # Run ClamAV scan and generate output
#     clamav_output = run_clamav_and_generate_output()
#     pdf.add_chapter('ClamAV Scan Summary', clamav_output)

#     # Run mass encryption check and generate output
#     mass_encryption_output = run_mass_encryption_and_generate_output()
#     pdf.add_chapter('Mass Encryption Check', mass_encryption_output)

#     # Run Lynis scan and generate output
#     lynis_output = run_lynis_and_generate_output()
#     pdf.add_chapter('System Scan with Lynis', lynis_output)

#     # Save the PDF to a file
#     pdf_output_path = '/home/vethavarshini/ransomware_detection_report.pdf'
#     pdf.output(pdf_output_path)
#     print(f"PDF report generated successfully: {pdf_output_path}")

# if __name__ == '__main__':
#     main()

import subprocess
import re
from rich.console import Console
from rich.table import Table
from pyfiglet import figlet_format
from tabulate import tabulate
from fpdf import FPDF
import os
from datetime import datetime

# Import the functions from each of your scripts
from clam import run_clamav_scan, parse_summary, display_summary, directories, directories_names
from mass import check_mass_encryption
from lynis_tool import run_lynis_scan

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Ransomware Detection Report', 0, 1, 'C')
        self.ln(10)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, body)
        self.ln()

    def add_chapter(self, title, body):
        self.add_page()
        self.chapter_title(title)
        self.chapter_body(body)

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def main():
    console = Console()
    pdf = PDFReport()

    # Step 1: Run ClamAV scans
    header = figlet_format("ClamAV Scan Summary", font="slant")
    console.print(header, style="bold green")
    clamav_output = ""
    for i, directory in enumerate(directories):
        scan_output = run_clamav_scan(directory)
        summary = parse_summary(scan_output)
        display_summary(summary, i)
        # Add to PDF
        clamav_output += f"ClamAV Scan Results for {directories_names[i]}:\n"
        for key, value in summary.items():
            clamav_output += f"{key}: {value}\n"
        clamav_output += "\n"
    
    pdf.add_chapter('ClamAV Scan Summary', clamav_output)

    # Step 2: Check for mass encryption
    directory_to_scan = '/home/vethavarshini/Downloads'
    scan_depth = 5
    console.print("\n" + figlet_format("Mass Encryption Check", font="slant"), style="bold yellow")
    encrypted_files = check_mass_encryption(directory=directory_to_scan, scan_depth=scan_depth)
    
    mass_encryption_output = ""
    if encrypted_files:
        mass_encryption_output = "Suspicious encrypted files detected:\n"
        mass_encryption_output += tabulate([[file] for file in encrypted_files], headers=["File Path"], tablefmt="grid")
    else:
        mass_encryption_output = "No suspicious encrypted files found."

    pdf.add_chapter('Mass Encryption Check', mass_encryption_output)

    # Step 3: Run Lynis system scan
    console.print("\n" + figlet_format("System Scan with Lynis", font="slant"), style="bold blue")
    scan_output = run_lynis_scan()
    scan_output_cleaned = remove_ansi_escape_sequences(scan_output)
    console.print(scan_output_cleaned)
    
    pdf.add_chapter('System Scan with Lynis', scan_output_cleaned)

    # Save the PDF to a file
    pdf_output_path = '/home/vethavarshini/ransomware_detection_report.pdf'
    pdf.output(pdf_output_path)
    print(f"PDF report generated successfully: {pdf_output_path}")

if __name__ == '__main__':
    main()
