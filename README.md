# File-Integrity-Monitoring-
A lightweight Python-based File Integrity Monitoring (FIM) system that can detect file additions, modifications, and deletions within a given directory.
It allows users to maintain a baseline snapshot of files and verify their integrity later.
Detected changes can be marked as authorized or unauthorized, with detailed JSON logs for integration with monitoring tools such as Wazuh.

# Features

**Baseline Creation:** Capture a snapshot of files in a directory, storing their SHA-256 hashes and last modified timestamps.
**Integrity Check:** Compare current state with the baseline to detect:
- File additions
- File modifications
- File deletions
**Authorization Prompt:** Decide if detected changes are authorized or unauthorized.
**JSON Logging:** All detected changes are logged in a structured JSON format, making them compatible with Wazuh or other SIEM tools.
**Customizable Paths:** Supports custom baseline and log file paths.

# Usage
Run the script with the following options:
- **Initialize a Baseline:**
  <pre> python fim.py init "C:\path\to\monitor"  </pre>
- **Check file Integrity:**
    <pre> python fim.py check "C:\path\to\monitor"  </pre>
