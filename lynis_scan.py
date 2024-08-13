import subprocess
import re
from rich.console import Console
from rich.table import Table
import pyfiglet

def run_lynis_scan():
    # Run Lynis scan and capture output
    result = subprocess.run(['sudo', 'lynis', 'audit', 'system'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def main():
    # Display CLI header
    header = pyfiglet.figlet_format("SYSTEM SCAN")
    print(header)

    # Run the Lynis scan
    scan_output = run_lynis_scan()
    print(scan_output)

if __name__ == '__main__':
    main()
