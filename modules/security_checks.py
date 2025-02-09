import ipaddress
import xml.etree.ElementTree as ET

from utilities import SEVERITY_ORDER, colored_text

def write_protocols_tab(file_path, workbook):

    print("Processing protocols from Nessus file...")
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        ws = workbook.create_sheet(title="Protocols")
        headers = ['Protocol', 'Host Count', 'Hosts']
        ws.append(headers)
        
        # We'll detect the protocols by port:
        port_map = {
            "5355": "LLMNR",
            "5353": "mDNS",
            "137":  "NBT-NS",
        }
        
        protocol_dict = {
            "LLMNR": set(),
            "mDNS": set(),
            "NBT-NS": set(),
            "IPv6": set(),
        }
        
        for ReportHost in root.findall('.//ReportHost'):
            # Grab IP address
            ip_address = ReportHost.find('HostProperties/tag[@name="host-ip"]')
            ip_address = (
                ip_address.text if ip_address is not None
                else ReportHost.attrib.get('name', 'Unknown IP')
            )
            
            # Check if the IP is IPv6:
            if ipaddress:
                try:
                    ip_obj = ipaddress.ip_address(ip_address)
                    if ip_obj.version == 6:
                        protocol_dict["IPv6"].add(ip_address)
                except ValueError:
                    pass

            # For each ReportItem, check if the port is in port_map
            for ReportItem in ReportHost.findall('.//ReportItem'):
                port = ReportItem.get('port', '')
                if port in port_map:
                    protocol_name = port_map[port]
                    protocol_dict[protocol_name].add(ip_address)
        
        # Now write them out in the order: LLMNR, mDNS, NBT-NS, IPv6
        for protocol_name in ["LLMNR", "mDNS", "NBT-NS", "IPv6"]:
            hosts = sorted(protocol_dict[protocol_name])
            if hosts:  # Only add rows for protocols that actually exist
                ws.append([
                    protocol_name,
                    len(hosts),
                    ', '.join(hosts)
                ])
        
        print("Finished processing protocols.")
        
    except Exception as e:
        print(f"Error processing protocols tab: {e}")

    pass

def write_missing_critical_patches(data_dict, workbook):

    ws = workbook.create_sheet(title="Missing Critical Patches")
    
    # Create headers
    headers = ['Patch', 'Severity', 'Host Count', 'Affected Hosts']
    ws.append(headers)
    
    # Filter for medium, high, and critical
    allowed_severities = {"Medium", "High", "Critical"}
    missing_patches = {
        name: data for name, data in data_dict.items()
        if data["Severity"] in allowed_severities
    }
    
    # Sort by severity first, then by host count
    sorted_patches = sorted(
        missing_patches.items(),
        key=lambda x: (
            SEVERITY_ORDER.get(x[1]["Severity"], 0),  # severity as primary
            len(x[1]['Affected Hosts'])               # host count as secondary
        ),
        reverse=True
    )
    
    for name, data in sorted_patches:
        host_count = len(data['Affected Hosts'])
        ws.append([
            name,              # Patch
            data['Severity'], # Severity
            host_count,        # Host Count
            ', '.join(data['Affected Hosts'])
        ])
        
    pass

def write_smb_signing_off(file_path, workbook):

    print("Processing SMB signing off hosts...")

    # We'll look for pluginName containing "SMB Signing" + "Not Required"
    SMB_MATCH_STRING = "smb signing"
    NOT_REQ_STRING = "not required"

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        print(colored_text(f"Error parsing Nessus file in write_smb_signing_off: {e}", "red"))
        return

    results = []  # Store tuples of (dns_name, ip_address)

    for report_host in root.iter("ReportHost"):
        ip_address = "Unknown IP"
        dns_name = "Unknown DNS"
        
        # Extract IP & DNS if available
        for tag in report_host.iter("tag"):
            if tag.attrib.get("name") == "host-ip":
                ip_address = tag.text
            elif tag.attrib.get("name") == "host-fqdn":
                dns_name = tag.text

        # Check each ReportItem for a matching plugin
        for item in report_host.iter("ReportItem"):
            plugin_name = item.attrib.get("pluginName", "")
            if (
                SMB_MATCH_STRING in plugin_name.lower()
                and NOT_REQ_STRING in plugin_name.lower()
            ):
                results.append((dns_name, ip_address))
                # Break so we don't list the same host multiple times
                break

    # Create a new sheet
    ws = workbook.create_sheet(title="SMB Signing Off")

    # Headers
    headers = ["Total Count", "DNS Name", "IP Address"]
    ws.append(headers)

    total_count = len(results)

    if total_count > 0:
        # Put the total count in the first column (row 2), leave DNS/IP blank
        ws.append([total_count, "", ""])
        # For each host, put DNS (col B) and IP (col C), and leave col A empty
        for (dns, ip) in results:
            ws.append(["", dns, ip])
    else:
        # If no hosts found, just show "0" in the second row
        ws.append([0, "", ""])

    print(f"Found {total_count} host(s) with SMB signing off.")
    
    pass


def write_unsupported_software(data_dict, workbook):

    ws = workbook.create_sheet(title="Unsupported Software")
    
    headers = ['Software Name', 'Severity', 'Host Count', 'Affected Hosts']
    ws.append(headers)
    
    # Filter for "unsupported" or "end of life"
    unsupported_software = {
        name: data for name, data in data_dict.items()
        if 'unsupported' in name.lower() or 'end of life' in name.lower()
    }
    
    # Sort by the length of the affected hosts list (descending)
    sorted_unsupported_software = sorted(
        unsupported_software.items(),
        key=lambda x: len(x[1]['Affected Hosts']),
        reverse=True
    )
    
    for name, data in sorted_unsupported_software:
        host_count = len(data['Affected Hosts'])
        ws.append([
            name,
            data['Severity'],
            host_count,
            ', '.join(data['Affected Hosts'])
        ])
    
    pass