# main_ransomware_detection.py

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

def main():
    # Step 1: Run ClamAV scans
    console = Console()
    header = figlet_format("ClamAV Scan Summary", font="slant")
    console.print(header, style="bold green")
    for i, directory in enumerate(directories):
        scan_output = run_clamav_scan(directory)
        summary = parse_summary(scan_output)
        display_summary(summary, i)

    # Step 2: Check for mass encryption
    directory_to_scan = '/home/vethavarshini/Desktop'
    scan_depth = 5
    console.print("\n" + figlet_format("Mass Encryption Check", font="slant"), style="bold yellow")
    check_mass_encryption(directory=directory_to_scan, scan_depth=scan_depth)

    # Step 3: Run Lynis system scan
    console.print("\n" + figlet_format("System Scan with Lynis", font="slant"), style="bold blue")
    scan_output = run_lynis_scan()
    print(scan_output)

if __name__ == '__main__':
    main()