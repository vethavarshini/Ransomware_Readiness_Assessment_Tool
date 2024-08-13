import os
from datetime import datetime
from termcolor import colored
from tabulate import tabulate

def check_mass_encryption(directory='/', scan_depth=3, exclude_dirs=None):
    # Comprehensive list of file extensions associated with ransomware
    encrypted_extensions = [
        '.encrypted', '.locked', '.enc', '.crypto', '.crypt', '.crypted',
        '.locky', '.zepto', '.cryptolocker', '.aes', '.ransom', '.cerber',
        '.crypto', '.crypt', '.lock', '.xtbl', '.tmp', '.ransomware', '.locker',
        '.glocker', '.gpd', '.gpd2', '.renamed', '.crypt', '.cryptor', '.djvu', 
        '.cry', '.jigsaw', '.vault', '.gpd', '.gpd2', '.blowfish', '.ztbl'
    ]
    encrypted_files = []

    if exclude_dirs is None:
        exclude_dirs = ['/proc', '/sys', '/dev']

    def is_recent(file_path, days=1):
        try:
            file_time = os.path.getmtime(file_path)
            return (datetime.now() - datetime.fromtimestamp(file_time)).days <= days
        except FileNotFoundErro+r:
            return False

    def search_directory(dir_path, current_depth=0):
        if current_depth > scan_depth:
            return
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclude_dirs]
            for file in files:
                if any(file.endswith(ext) for ext in encrypted_extensions):
                    file_path = os.path.join(root, file)
                    if is_recent(file_path, days=365):  # Check files modified in the last year
                        encrypted_files.append(file_path)

    print(colored("Scanning directory for potential mass encryption...", 'blue'))
    search_directory(directory)
    
    # Create a table to display the results
    table_headers = ["File Path"]
    table_data = [[file] for file in encrypted_files]
    
    if encrypted_files:
        print(colored("\nSuspicious encrypted files detected:", 'red'))
        table = tabulate(table_data, headers=table_headers, tablefmt='fancy_grid', stralign='left')
        # Apply background color to the table
        table_with_bg = "\033[48;5;16m" + table + "\033[0m"
        print(colored(table_with_bg, 'yellow'))
        print(colored(f"\nTotal suspicious encrypted files found: {len(encrypted_files)}", 'red'))
    else:
        print(colored("No suspicious encrypted files found.", 'green'))

    return encrypted_files

# Usage:
if __name__ == "__main__":
    directory_to_scan = '/home/kali/Downloads'
    scan_depth = 5
    check_mass_encryption(directory=directory_to_scan, scan_depth=scan_depth)
