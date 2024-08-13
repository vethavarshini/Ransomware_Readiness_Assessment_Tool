import subprocess
import re
from rich.console import Console
from rich.table import Table
from pyfiglet import figlet_format

#list of directories
directories = [
    #'/home/username/Desktop/',
    #'/home/username/Downloads/'

]
directories_names=['Desktop','Home','Documents','Downloads']
def run_clamav_scan(directory):
    # Run ClamAV scan using subprocess
    result = subprocess.run(['clamscan',directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def parse_summary(output):
    # Regex to find the summary information in ClamAV output
    engine_version = re.search(r'Engine version:\s*(\S+)', output).group(1)
    scanned_directories = re.search(r'Scanned directories:\s*(\d+)', output).group(1)
    scanned_files = re.search(r'Scanned files:\s*(\d+)', output).group(1)
    infected_files = re.search(r'Infected files:\s*(\d+)', output).group(1)
    data_scanned = re.search(r'Data scanned:\s*([\d.]+ MB)', output).group(1)
    data_read = re.search(r'Data read:\s*([\d.]+ MB)', output).group(1)
    time = re.search(r'Time:\s*([\d.]+ sec)', output).group(1)
    start_date = re.search(r'Start Date:\s*(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})', output).group(1)
    end_date = re.search(r'End Date:\s*(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})', output).group(1)

    return {
        'Engine Version': engine_version,
        'Scanned Directories': scanned_directories,
        'Scanned Files': scanned_files,
        'Infected Files': infected_files,
        'Data Scanned': data_scanned,
        'Data Read': data_read,
        'Time': time,
        'Start Date': start_date,
        'End Date': end_date
    }

def display_summary(summary,i):
    # Initialize the rich console
    console = Console()
    # Create a table
    table = Table(title=f"ClamAV Scan Results for {directories_names[i]}")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    # Add rows to the table
    for key, value in summary.items():
        table.add_row(key, value)

    # Print the table
    console.print(table)

def main():
    # Print the header with pyfiglet
    i=0
    console = Console()
    header = figlet_format("ClamAV Scan Summary", font="slant")
    console.print(header, style="bold green")
    for directory in directories:
        
        scan_output = run_clamav_scan(directory)
    
    # Parse the summary from scan output
        summary = parse_summary(scan_output)
    
    # Display the summary in a table
        display_summary(summary,i)
        i+=1

if __name__ == '__main__':
    main()
