import xml.etree.ElementTree as ET

def sort_worksheet_by_severity(ws, severity_column="B"):
    # Convert column letter to index
    severity_col_index = ws[severity_column][0].column

    # Read all rows into a list, skip the header
    data = list(ws.iter_rows(values_only=True))
    header, rows = data[0], data[1:]

    # Sort rows by the severity column (assuming severity is in text format, e.g., 'Critical', 'High', etc.)
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}
    rows.sort(key=lambda row: severity_order.get(row[severity_col_index - 1], 6))

    # Clear the worksheet and write the sorted rows back
    for row_index, row in enumerate([header] + rows, start=1):
        for col_index, value in enumerate(row, start=1):
            ws.cell(row=row_index, column=col_index, value=value)
    pass
        
def extract_host_data(nessus_file, sheet_name, workbook):
    try:
        print(f"Processing {sheet_name} from {nessus_file}...")

        # Parse the Nessus XML
        tree = ET.parse(nessus_file)
        root = tree.getroot()

        # Create a new worksheet
        ws = workbook.create_sheet(title=sheet_name)

        # Define headers
        headers = ["IP Address", "DNS/Hostname"]
        ws.append(headers)

        # Extract IP and DNS/Hostname data
        for report_host in root.findall(".//ReportHost"):
            ip_address = None
            hostname = None

            # Look for IP address and hostname in the host properties
            for tag in report_host.findall(".//tag"):
                if tag.get("name") == "host-ip":
                    ip_address = tag.text
                elif tag.get("name") == "host-fqdn":
                    hostname = tag.text

            # Append the data if an IP address is found
            if ip_address:
                ws.append([ip_address, hostname or "Unknown"])

        print(f"Successfully processed {sheet_name}.")

    except Exception as e:
        print(f"Error processing {sheet_name}: {e}")
    
    pass
    