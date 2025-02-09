import json
import os

from utilities import colored_text

def is_valid_customization(file_path):
    """Check if the provided file path is a valid .customization file."""
    return os.path.isfile(file_path) and file_path.endswith('.customization')

def append_customization_data(custom_file, workbook):
    
    with open(custom_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    external_rows = []
    internal_rows = []

    # Separate external vs internal
    for vuln in vulns:
        title = vuln.get("title", "Unknown Title")
        severity = vuln.get("priority", "Unknown Severity")
        recommendation = vuln.get("remediation_recommendation", "")
        
        # Build the Affected Hosts string
        affected_assets = vuln.get("affected_assets", [])
        hosts = []
        is_internal = False

        for asset_entry in affected_assets:
            host_name = asset_entry.get("asset", "Unknown Host")
            hosts.append(host_name)
            # Check tags to see if it's internal
            for tag_dict in asset_entry.get("assetCustomTags", []):
                if tag_dict.get("Internal") == "true":
                    is_internal = True

        row_data = [
            title,                   # Vulnerability Name
            severity,               # Severity
            ", ".join(hosts),       # Affected Hosts
            recommendation          # Recommendations
        ]
        
        if is_internal:
            internal_rows.append(row_data)
        else:
            external_rows.append(row_data)

    # Append to "External Scan"
    if "External Scan" in workbook.sheetnames:
        ws_ext = workbook["External Scan"]
        for row in external_rows:
            ws_ext.append(row)
        print(f"{colored_text('Appended', 'white')} {colored_text(len(external_rows), 'green')} {colored_text('vulnerabilities', 'white')} to {colored_text('External Scan', 'green')} tab.")
    else:
        print(colored_text("Warning: 'External Scan' sheet not found. No external data appended.", "red"))

    # Append to "Internal Scan"
    if "Internal Scan" in workbook.sheetnames:
        ws_int = workbook["Internal Scan"]
        for row in internal_rows:
            ws_int.append(row)
        print(f"{colored_text('Appended', 'white')} {colored_text(len(internal_rows), 'green')} {colored_text('vulnerabilities', 'white')} to {colored_text('Internal Scan', 'green')} tab.")
    else:
        print(colored_text("Warning: 'Internal Scan' sheet not found. No Internal data appended.", "red"))