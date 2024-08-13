<h1>Ransomware Readiness Assessment Tool</h1>

  <p>The <strong>Ransomware Readiness Assessment Tool</strong> is a comprehensive application designed to detect and evaluate potential ransomware threats. The tool combines multiple scanning and assessment methods, including ClamAV antivirus scanning, mass encryption detection, and system auditing with Lynis.</p>

  <h2>Features</h2>
  <ul>
    <li><strong>ClamAV Scanning:</strong> Performs deep scans of directories to detect and report infected files.</li>
    <li><strong>Mass Encryption Detection:</strong> Identifies files that have been recently encrypted, indicating potential ransomware activity.</li>
    <li><strong>Lynis System Audit:</strong> Conducts a system audit to check for vulnerabilities and outdated files.</li>
    <li><strong>Risk Assessment:</strong> Collects user inputs to evaluate the system's risk based on antivirus presence, backup history, and previous ransomware attacks.</li>
    <li><strong>PDF Summary Report:</strong> Generates a downloadable PDF summary of the assessment results.</li>
  </ul>

  <h2>Prerequisites</h2>
  <ul>
    <li>Python 3.x</li>
    <li>Libraries: <code>tkinter</code>, <code>threading</code>, <code>fpdf</code>, <code>re</code></li>
    <li><strong>ClamAV</strong> installed on the system</li>
    <li><strong>Lynis</strong> installed on the system</li>
  </ul>

  <h2>Installation</h2>
  <ol>
    <li>Clone the repository:
      <pre><code>git clone https://github.com/your-username/ransomware-readiness-assessment.git
cd Ransomware_Readiness_Assessment_Tool</code></pre>
    </li>
    <li>Install the required Python packages:
      <pre><code>pip install termcolor tabulate rich pyfiglet</code></pre>
    </li>
    <li>Ensure <strong>ClamAV</strong> and <strong>Lynis</strong> are installed on your system:
      <ul>
        <li>For ClamAV:
          <pre><code>sudo apt-get install clamav</code></pre>
        </li>
        <li>For Lynis:
          <pre><code>sudo apt-get install lynis</code></pre>
        </li>
      </ul>
    </li>
  </ol>

  <h2>Usage</h2>
  <h3>Running the Application</h3>
  <ol>
    <li>Run the main application script:
      <pre><code>sudo python3 code_1.py</code></pre>
    </li>
    <li>The application will start, displaying the main GUI window.</li>
    <li>Click the "SCAN FOR RANSOMWARE" button to begin the scan.</li>
    <li>Review the results in the output area.</li>
    <li>After the scan completes, you can download the assessment summary as a PDF by clicking the "Download Assessment Summary" button.</li>
  </ol>

  <h3>CLI Usage (Optional)</h3>
  <p>If you prefer to use the CLI for testing purposes, you can run the following scripts:</p>
  <ul>
    <li><strong>ClamAV Scan:</strong> 
      <pre><code>python main_ransomware_detection.py</code></pre>
    </li>
  </ul>
  
  <h2>Troubleshooting</h2>
  <ul>
    <li><strong>Module Not Found:</strong> Ensure all required Python libraries are installed.</li>
    <li><strong>Permission Issues:</strong> Running Lynis or ClamAV may require <code>sudo</code> privileges.</li>
    <li><strong>No Suspicious Files Found:</strong> This could mean your system is currently not infected, but regular scans are recommended.</li>
  </ul>
