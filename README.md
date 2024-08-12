# Ransomware_Readiness_Assessment_Tool

# Ransomware Readiness Assessment Tool

The **Ransomware Readiness Assessment Tool** is a comprehensive application designed to detect and evaluate potential ransomware threats. The tool combines multiple scanning and assessment methods, including ClamAV antivirus scanning, mass encryption detection, and system auditing with Lynis.

## Features
- **ClamAV Scanning:** Performs deep scans of directories to detect and report infected files.
- **Mass Encryption Detection:** Identifies files that have been recently encrypted, indicating potential ransomware activity.
- **Lynis System Audit:** Conducts a system audit to check for vulnerabilities and outdated files.
- **Risk Assessment:** Collects user inputs to evaluate the system's risk based on antivirus presence, backup history, and previous ransomware attacks.
- **PDF Summary Report:** Generates a downloadable PDF summary of the assessment results.

## Prerequisites
- Python 3.x
- Libraries: `tkinter`, `threading`, `fpdf`, `re`
- **ClamAV** installed on the system
- **Lynis** installed on the system

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/ransomware-readiness-assessment.git
   cd ransomware-readiness-assessment
