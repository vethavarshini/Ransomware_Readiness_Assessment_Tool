import subprocess
import re
from rich.console import Console
from rich.table import Table
from pyfiglet import figlet_format
from termcolor import colored
from tabulate import tabulate
import os
from datetime import datetime

# Import the functions from each of your scripts
from clam import run_clamav_scan, parse_summary, display_summary, directories, directories_names
from mass import check_mass_encryption
from lynis_tool import run_lynis_scan

def get_user_inputs():
    """Prompt user for antivirus, backup, and ransomware history."""
    antivirus = input("Do you have Antivirus software? (yes/no): ").strip().lower()
    last_backup = input("When was your last backup done? (please enter in YYYY-MM-DD format): ").strip()
    ransomware_attack = input("Have you ever faced any Ransomware attack before? (yes/no): ").strip().lower()

    return antivirus, last_backup, ransomware_attack

def assess_risk(antivirus, last_backup, ransomware_attack, encrypted_files, infected_files):
    """Generate and print risk summary based on user inputs and scan results."""
    risk_summary = []

    # Check antivirus status
    if antivirus != 'yes':
        risk_summary.append("Risk: High - Antivirus software is not installed.")

    # Check backup status
    try:
        backup_date = datetime.strptime(last_backup, '%Y-%m-%d')
        days_since_backup = (datetime.now() - backup_date).days
        if days_since_backup > 30:  # Assuming a safe backup period is within the last 30 days
            risk_summary.append(f"Risk: High - Last backup was done {days_since_backup} days ago, which is too long.")
    except ValueError:
        risk_summary.append("Risk: High - Invalid date format for last backup.")

    # Check ransomware attack history
    if ransomware_attack == 'yes':
        risk_summary.append("Risk: High - Previous ransomware attack history increases the risk.")

    # Check mass encryption files
    if encrypted_files:
        risk_summary.append("\nSuspicious encrypted files detected:")
        for file in encrypted_files:
            risk_summary.append(f"  - {file}")

    # Check infected files from ClamAV
    if infected_files:
        risk_summary.append("\nMALICIOUS FILE DETECTED:POSSIBLY A RANSOMEWARE")
        for file in infected_files:
            risk_summary.append(f"  - {file}")

    # Display risk summary
    if risk_summary:
        print(colored("\nRansomware Risk Assessment Summary:", 'red'))
        for line in risk_summary:
            print(colored(line, 'red'))
        return risk_summary
    else:
        print(colored("\nRansomware Risk Assessment Summary: Your system appears to be at low risk based on the provided information.", 'green'))

def main():
    # Step 1: Run ClamAV scans
    console = Console()
    header = figlet_format("ClamAV Scan Summary", font="slant")
    console.print(header, style="bold green")
    
    infected_files = []  # List to hold paths of infected files
    for i, directory in enumerate(directories):
        scan_output = run_clamav_scan(directory)
        summary = parse_summary(scan_output)
        display_summary(summary, i)
        if int(summary['Infected Files']) > 0:
            # Collect infected files from scan output
            infected_files.extend(re.findall(r'^(.*?):\s*.*\s*FOUND', scan_output, re.MULTILINE))

    # Step 2: Check for mass encryption
    directory_to_scan = '/home/vethavarshini/Desktop'
    scan_depth = 5
    console.print("\n" + figlet_format("Mass Encryption Check", font="slant"), style="bold yellow")
    encrypted_files = check_mass_encryption(directory=directory_to_scan, scan_depth=scan_depth)

    # Step 3: Run Lynis system scan
    console.print("\n" + figlet_format("System Scan with Lynis", font="slant"), style="bold blue")
    scan_output = run_lynis_scan()
    print(scan_output)

    # Step 4: User input and risk assessment
    antivirus, last_backup, ransomware_attack = get_user_inputs()
    assess_risk(antivirus, last_backup, ransomware_attack, encrypted_files, infected_files)

if __name__ == '__main__':
    main()
