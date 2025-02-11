import xml.etree.ElementTree as ET
import argparse
import re

def parse_nessus_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    target_processes = ["TeamViewer", "remote", "Mikogo", "screenconnect", "atera", "goto", 
                        "ISL Online", "LogMeIn", "LogMeIn Pro", "LogMeIn Central", 
                        "LogMeInRescue", "GoToMyPC", "Dameware Remote Support", 
                        "Dameware Remote Everywhere", "Dameware Mini Remote Control", 
                        "Parallels", "Mikogo"]

    results = {}

    for ReportHost in root.findall('.//ReportHost'):
        ip_address = ReportHost.find('HostProperties/tag[@name="host-ip"]').text if ReportHost.find('HostProperties/tag[@name="host-ip"]') is not None else "Unknown IP"
        hostname = "Unknown Hostname"
        
        # Checking for Device Hostname plugin
        for host_property in ReportHost.findall('HostProperties/tag'):
            if host_property.get('name') == 'host-fqdn':
                hostname = host_property.text
                break

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

    with open("processes.txt", "w") as file:
        for ip, info in sorted(results.items()):
            process_list = ', '.join(info['processes'])
            result = f"IP Address: {ip}, Hostname: {info['hostname']}, Processes: {process_list}\n"
            print(result.strip())
            file.write(result)

def main():
    parser = argparse.ArgumentParser(description='Parse a Nessus file for specific processes.')
    parser.add_argument('-f', '--file', type=str, required=True, help='Path to the Nessus file')
    args = parser.parse_args()

    parse_nessus_file(args.file)

if __name__ == "__main__":
    main()