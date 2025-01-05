# Nessus Report Parser

This Python script parses Nessus (`.nessus`) files to generate a multi-tab Excel report. It includes features for identifying vulnerabilities, processes, protocols, and more in both **internal** and **external** Nessus scans. Additionally, it can parse a AttackForge  (`.customization`) files to append extra vulnerability data into the same report.

## Features

1. **External Scan** (Tab: **External Scan**)  
   - Parses an external Nessus file (`-e`) for vulnerabilities (excluding Informational).  
   - Lists vulnerability name, severity, affected hosts, and recommendations.

2. **Internal Scan** (Tab: **Internal Scan**)  
   - Parses an internal Nessus file (`-i`) the same way, listing vulnerabilities.  
   - Creates additional tabs:
     - **Remote Access Processes** - identifies hosts with remote access sofware such as TeamViewer, ScreenConnect, etc.
     - **Unsupported Software** - identifies hosts with unsupported software such as Windows XP, Windows 2000, etc. 
     - **Missing Critical Patches** - identifies hosts with missing critical patches. 
     - **Protocols** - (LLMNR, mDNS, NBT-NS, IPv6)  
     - **Internal Port Table** - (DNS Name, IP, Open Ports, plus optional columns)  
     - **SMB Signing Off** - identifies hosts with SMB signing turned off.

3. **Port Tables**  
   - **External Port Table**  
     - DNS Name, IP Address, Open Ports, Port Info, URLs  
   - **Internal Port Table**  
     - DNS Name, IP Address, Open Ports, URLs

4. **Customization Data** (JSON, `.customization`)  
   - If provided via `-a`, the script appends additional vulnerabilities to **External Scan** and **Internal Scan** tabs.

5. **Color-Coding**  
   - Rows with severity **Critical**, **High**, **Medium**, **Low**, or **Informational** are automatically highlighted according to pre-defined colors.

6. **Auto-Styling**  
   - Automatic column-width adjustments (heuristic).  
   - Freezes the first two columns (`A`, `B`) on “External Scan” and “Internal Scan” tabs for easy navigation.

7. **[ NEW!! ]** **Bloodhound**
   - Will find the Bloodhound data in the Nessus file and create a new tab with the data.
   - Currently only finds kerberoastable users and their associated SPNs, ASREProastable users and their associated SPNs, Users with Unconstrained Delegation, Users with RBCD. (MORE TO COME).

## Requirements

- **Python 3.6+**
- **Packages**:
  - `openpyxl` (for Excel writing)
  - `xml.etree.ElementTree` (standard library)
  - `ipaddress` (standard library in Python 3.3+, fallback if on older versions)

# Install
```bash
pip install openpyxl
```
# Usage
##### python3 nessusparser.py [options]
```bash
Command-Line Arguments
Argument	Description	Example
-e/--external	Path to the external Nessus file (.nessus).	-e external_scan.nessus
-i/--internal	Path to the internal Nessus file (.nessus).	-i internal_scan.nessus
-a/--attackforge	Path to the .customization (AttackForge) file for appending vulnerabilities. -a extra_vulns.customization
-b/--bloodhound	Path to the .zip file to extract Bloodhound data from. -b bloodhound_scan.zip
-o/--output	Output Excel file name. (Defaults to Nessus_Report.xlsx.) -o My_Report.xlsx
Note: You must provide at least one of -e, -i, -b or -a. Any combination is valid.
```

# Example Usage
```bash
python nessus_report_parser.py --external external_scan.nessus
python nessus_report_parser.py --internal internal_scan.nessus
python nessus_report_parser.py -e external_scan.nessus -i internal_scan.nessus
python nessus_report_parser.py -i internal_scan.nessus -a extra_vulns.customization
python nessus_report_parser.py -e external_scan.nessus -i internal_scan.nessus -a extra_vulns.customization -o final_report.xlsx
python nessus_report_parser.py -e external_scan.nessus -i internal_scan.nessus -a extra_vulns.customization -b bloodhound.zip -o final_report.xlsx
```

# Output

```bash
The script generates an Excel file (default: Nessus_Report.xlsx) with multiple tabs:

- External Scan
- Internal Scan
- Remote Access Processes (internal only)
- Unsupported Software (internal only)
- Missing Critical Patches (internal only)
- Protocols (internal only)
- External Port Table (external only)
- Internal Port Table (internal only)
- SMB Signing Off (internal only)
- Appended vulnerabilities from a .customization file (merged into “External Scan” / “Internal Scan”).
- Bloodhound data (if bloodhound.zip is provided and there are findings).
```

Severity-based color highlighting and column auto-sizing provide clarity for analyzing results.
```

# Notes and Limitations
```bash
* Informational findings (severity 0) are skipped by default.
* The script uses heuristics to identify certain findings and protocols; adjust if needed.
* For SMB signing, we look for plugin names containing "SMB Signing" and "Not Required" (case-insensitive).
* The column auto-fit is approximate and may not perfectly match manual “AutoFit” in Excel.
```


