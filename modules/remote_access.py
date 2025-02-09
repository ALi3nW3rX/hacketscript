import xml.etree.ElementTree as ET
import re

from utilities import colored_text

def write_processes_tab(file_path, workbook):
    print("Processing remote access processes...")
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        ws = workbook.create_sheet(title="Remote Access Processes")
        headers = ['IP Address', 'Hostname', 'Remote Access Processes']
        ws.append(headers)
        
        # Define target processes to look for
        target_processes = [
            "TeamViewer", "remote", "Mikogo", "screenconnect", "atera", "goto", 
            "ISL Online", "LogMeIn", "LogMeIn Pro", "LogMeIn Central", 
            "LogMeInRescue", "GoToMyPC", "Dameware Remote Support", 
            "Dameware Remote Everywhere", "Dameware Mini Remote Control", 
            "Parallels", "Mikogo"
        ]

        results = {}

        for ReportHost in root.findall('.//ReportHost'):
            # Get IP address
            ip_address = ReportHost.find('HostProperties/tag[@name="host-ip"]')
            ip_address = ip_address.text if ip_address is not None else "Unknown IP"
            
            hostname = "Unknown Hostname"
            for host_property in ReportHost.findall('HostProperties/tag'):
                if host_property.get('name') == 'host-fqdn':
                    hostname = host_property.text
                    break

            # Look for process information
            for ReportItem in ReportHost.findall('.//ReportItem'):
                plugin_name = ReportItem.get('pluginName')
                if plugin_name == "Microsoft Windows Process Information":
                    process_info = ReportItem.find('plugin_output')
                    if process_info is not None:
                        found_processes = re.findall(r'[\w.-]+\.exe', process_info.text, re.IGNORECASE)
                        for found_process in found_processes:
                            for process in target_processes:
                                if process.lower() in found_process.lower():
                                    if ip_address not in results:
                                        results[ip_address] = {'hostname': hostname, 'processes': set()}
                                    results[ip_address]['processes'].add(found_process)

        # Write results to Excel
        for ip, info in sorted(results.items()):
            process_list = ', '.join(info['processes'])
            ws.append([ip, info['hostname'], process_list])

    except Exception as e:
        print(colored_text(f"Error processing processes tab: {e}", "red"))
        
    pass