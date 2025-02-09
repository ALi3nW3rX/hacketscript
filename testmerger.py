import xml.etree.ElementTree as ET
import os
import sys

def merge_nessus_files(input_dir, output_file):
    """
    Merges multiple .nessus files from a directory into a single .nessus file.
    """
    nessus_element = ET.Element("NessusClientData_v2")
    policy_element = ET.SubElement(nessus_element, "Policy")
    report_element = ET.SubElement(nessus_element, "Report")

    for filename in os.listdir(input_dir):
        if filename.endswith(".nessus"):
            filepath = os.path.join(input_dir, filename)
            try:
                tree = ET.parse(filepath)
                root = tree.getroot()

                # Append the Policy element only from the first file
                if policy_element.find('policyReport') is None:
                    policy_from_file = root.find('Policy')
                    if policy_from_file is not None:
                        policy_element.append(policy_from_file[0])
                
                # Append all Report elements
                for report in root.findall('Report'):
                     for child in report:
                        report_element.append(child)
            except ET.ParseError as e:
                print(f"Error parsing {filename}: {e}")
            except Exception as e:
                 print(f"Unexpected error processing {filename}: {e}")
            
    tree = ET.ElementTree(nessus_element)
    ET.indent(tree, space="\t", level=0)
    tree.write(output_file, encoding="UTF-8", xml_declaration=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python merge_nessus.py <input_directory> <output_file>")
        sys.exit(1)

    input_directory = sys.argv[1]
    output_filepath = sys.argv[2]

    if not os.path.isdir(input_directory):
        print(f"Error: Input directory '{input_directory}' does not exist.")
        sys.exit(1)
    
    merge_nessus_files(input_directory, output_filepath)
    print(f"Successfully merged .nessus files into: {output_filepath}")