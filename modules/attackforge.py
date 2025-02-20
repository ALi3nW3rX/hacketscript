import json
import os
from utilities import colored_text

def is_valid_customization(file_path):
    """Check if the provided file path is a valid .customization file."""
    return os.path.isfile(file_path) and file_path.endswith('.customization')

def append_customization_data(custom_file, workbook, use_external=True, use_internal=True):
    with open(custom_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    external_rows = []
    internal_rows = []
    
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

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

    def insert_sorted(worksheet, new_rows):
        existing_data = list(worksheet.iter_rows(min_row=2, values_only=True))
        all_data = existing_data + new_rows
        sorted_data = sorted(all_data, key=lambda x: severity_order.get(x[1], 5))

        for row, entry in enumerate(sorted_data, start=2):
            for col, value in enumerate(entry, start=1):
                worksheet.cell(row=row, column=col, value=value)

        return len(new_rows)

    if use_external:
        if "External Scan" in workbook.sheetnames:
            ws_ext = workbook["External Scan"]
            inserted_count = insert_sorted(ws_ext, external_rows)
            print(f"{colored_text('Inserted', 'white')} {colored_text(inserted_count, 'green')} {colored_text('vulnerabilities', 'white')} to {colored_text('External Scan', 'green')} tab.")
        

    if use_internal:
        if "Internal Scan" in workbook.sheetnames:
            ws_int = workbook["Internal Scan"]
            inserted_count = insert_sorted(ws_int, internal_rows)
            print(f"{colored_text('Inserted', 'white')} {colored_text(inserted_count, 'green')} {colored_text('vulnerabilities', 'white')} to {colored_text('Internal Scan', 'green')} tab.")
        
