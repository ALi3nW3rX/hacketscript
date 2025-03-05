import xml.etree.ElementTree as ET

from utilities import SEVERITY_MAP, colored_text, get_cvss2_severity, get_cvss3_severity



def parse_nessus_file(file_path):
    """Parses a Nessus file and maps severity levels correctly."""
    try:
        print("\r" + colored_text("Parsing Nessus File:", "white") + " " + colored_text(file_path, "green") + "\n", end="")
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(colored_text(f"Error: Unable to parse the .nessus file: {file_path}.\nDetails: {e}", "red"))
        return {}

    vuln_dict = {}
    report_hosts = list(root.iter('ReportHost'))
    print(colored_text("Found", "white") + " " + colored_text(str(len(report_hosts)), "green") + " " + colored_text("hosts in the", "white") + " " + colored_text("Nessus file", "green"))

    # Parse host information using `parse_port_info`
    host_info = parse_port_info(file_path)

    for host in report_hosts:
        hostname = host.attrib.get('name', '')

        for block in host.iter('ReportItem'):
            plugin_name = block.attrib.get('pluginName', '')
            port = block.attrib.get('port', '')

            # Debug: Print every plugin name and port to confirm what we are parsing
            #print(f"[DEBUG] Found ReportItem - Plugin: {plugin_name}, Port: {port}")

            # Extract CVSS Scores
            cvss3_base_score = block.findtext('cvss3_base_score')
            cvss2_base_score = block.findtext('cvss_base_score')
            risk_factor = block.findtext('risk_factor')

            # Convert score strings to float (if available)
            if cvss3_base_score:
                try:
                    cvss3_score_float = float(cvss3_base_score)
                    severity_label = get_cvss3_severity(cvss3_score_float)

                    # 🛠️ Override if Nessus explicitly labeled it as "Critical"
                    nessus_severity = block.attrib.get('severity', '0')  # Get Nessus severity
                    if (nessus_severity == "4" or (risk_factor and risk_factor.lower() == "critical")) and severity_label != "Critical":
                        severity_label = "Critical"  # Force it to match Nessus' classification
                        #print(f"[OVERRIDE] {plugin_name} - Nessus marked this as Critical. Overriding {severity_label} -> Critical.")

                except ValueError:
                    #print(f"[ERROR] Could not convert CVSS v3.0 score: {cvss3_base_score} for {plugin_name}")
                    severity_label = "Unknown"
            elif cvss2_base_score:
                try:
                    cvss2_score_float = float(cvss2_base_score)
                    severity_label = get_cvss2_severity(cvss2_score_float)
                except ValueError:
                    #print(f"[ERROR] Could not convert CVSS v2.0 score: {cvss2_base_score} for {plugin_name}")
                    severity_label = "Unknown"
            else:
                # Fallback to legacy Nessus severity mapping
                severity = block.attrib.get('severity', '0')
                severity_label = SEVERITY_MAP.get(severity, "Unknown")
                #print(f"[DEBUG] Plugin: {plugin_name} - Legacy Severity Mapping: {severity} -> {severity_label}")  # Debug Print
  # Debug Print


            # Skip all 'Informational' findings
            if severity_label == "Informational":
                continue

            host_port = f"{hostname}:{block.attrib.get('port', '')}"

            if plugin_name not in vuln_dict:
                vuln_dict[plugin_name] = {
                    'Severity': severity_label,
                    'Affected Hosts': [host_port],
                    'Host Info': host_info,
                    'Recommendations': block.findtext('solution', ''),
                    'Description': block.findtext('description', '')
                }
            else:
                if host_port not in vuln_dict[plugin_name]['Affected Hosts']:
                    vuln_dict[plugin_name]['Affected Hosts'].append(host_port)

    print(colored_text("Parsed", "white") + " " + colored_text(str(len(vuln_dict)), "green") + " " + colored_text("vulnerabilities from the", "white") + " " + colored_text("Nessus file.", "green"))
    return vuln_dict

pass

def parse_port_info(nessus_file):
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    host_info = []

    # Iterate through each ReportHost
    for report_host in root.iter("ReportHost"):
        host_ip = ""
        dns_name = ""
        tcp_ports = set()
        udp_ports = set()
        port_details = {}

        # Extract the host IP and DNS name
        for tag in report_host.iter("tag"):
            if tag.attrib.get("name") == "host-ip":
                host_ip = tag.text
            elif tag.attrib.get("name") == "host-fqdn":
                dns_name = tag.text

        # Iterate through ReportItems to find open ports
        www_urls = set()
        for item in report_host.iter("ReportItem"):
            port = item.attrib["port"]
            protocol = item.attrib["protocol"]
            svc_name = item.attrib.get("svc_name", "Unknown Service")
            plugin_output = item.find("plugin_output")
            cpe = item.find("cpe")

            # Use Nessus-reported service name if available
            detected_service = svc_name.upper()
            if plugin_output is not None and plugin_output.text.strip():
                detected_service = plugin_output.text.split("\n")[0]
            elif cpe is not None and cpe.text:
                detected_service = cpe.text

            if port == "0":
                continue

            if protocol.lower() == "tcp":
                tcp_ports.add(port)
            elif protocol.lower() == "udp":
                udp_ports.add(port)

                # Check if a URL exists for this port
            url_exists = any(
                url in www_urls for url in [f"http://{host_ip}:{port}", f"https://{host_ip}:{port}"]
            )

            if url_exists:
                port_details[port] = f"Port {port} appears to be associated with a web server that responds with."
            elif "?" in detected_service:
                port_details[port] = f"Unable to fingerprint a running service on Port {port}."
            else:
                port_details[port] = f"Port {port} appears to be associated with {detected_service}."

 
                if (
                    port in {"80", "443", "8080", "8443", "9443", "10443"} or
                    any(word in detected_service.lower() for word in ["http", "www", "https", "ssl", "web"])
                ):
                    if port in {"443", "8443", "9443", "10443"} or "https" in detected_service.lower() or "ssl" in detected_service.lower():
                        url = f"https://{host_ip}:{port}"
                    else:
                        url = f"http://{host_ip}:{port}"
                    www_urls.add(url)
                    
        # Build the "Open Ports" string
        open_ports_str = []
        if tcp_ports:
            open_ports_str.append("TCP: " + ", ".join(sorted(tcp_ports)))
        if udp_ports:
            open_ports_str.append("UDP: " + ", ".join(sorted(udp_ports)))
        open_ports_str = "\n".join(open_ports_str)

        # Combine per-port messages (Port Info)
        port_info_str = "\n".join(port_details.values())

        # Build URLs
        url_str = "\n".join(sorted(www_urls))
        # Debugging: Print the URLs for each host
        
        if open_ports_str:  # Only add hosts that have open ports
            host_info.append({
                "DNS Name": dns_name or "",
                "IP Address": host_ip or "",
                "Open Ports": open_ports_str,
                "Port Info": port_info_str,
                "URLs": url_str
            })

    return host_info
pass