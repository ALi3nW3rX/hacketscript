#!/usr/bin/env python3
import os
import sys
import argparse
import openpyxl


# Add the modules directory to the system path
sys.path.insert(0, os.path.abspath("modules"))

# Import necessary modules
from combined import combine_nessus_files
from data_processors import extract_host_data
from utilities import SEVERITY_MAP, SEVERITY_ORDER, colored_text, bold_text
from file_parsers import parse_nessus_file, parse_port_info
from excel_writer import write_to_excel, write_port_table, apply_workbook_styling, SEVERITY_FILL_COLORS
from bloodhound_parser import parse_bloodhound_zip
from attackforge import append_customization_data
from osint_importer import import_osint_report
from banner import display_banner
from security_checks import write_missing_critical_patches, write_protocols_tab, write_smb_signing_off, write_unsupported_software, write_processes_tab


def parse_arguments():
    parser = argparse.ArgumentParser(description="Hacket - Nessus & OSINT Report Generator")
    parser.add_argument("-i", "--internal", help="Path to the internal Nessus scan file")
    parser.add_argument("-e", "--external", help="Path to the external Nessus scan file")
    parser.add_argument("-os", "--osint", help="Path to the OSINT .xlsx file to import")
    parser.add_argument("-a", "--attackforge", help="Path to the AttackForge .customization file")
    parser.add_argument("-b", "--bloodhound", help="Path to the BloodHound .zip file")
    parser.add_argument("-c", "--combine", help="Directory of .nessus files to merge")
    parser.add_argument("-o", "--output", help="Output Excel file name", default="Nessus_Report.xlsx")
    return parser.parse_args()

def process_files(args, workbook):
    print("Processing files...")
    print("-" * 60)
    
    if args.external:
        if not os.path.isfile(args.external) or not args.external.lower().endswith('.nessus'):
            print("Error: External file is not a valid .nessus file.")
        else:
            print(f"Processing Nessus File: {args.external}")
            external_data = parse_nessus_file(args.external)
            write_to_excel(external_data, 'External Scan', workbook)
            write_port_table(args.external, workbook, "External Port Table", is_external=True)
            extract_host_data(args.external, "External Host Data", workbook)
             
    
    if args.internal:
        if not os.path.isfile(args.internal) or not args.internal.lower().endswith('.nessus'):
            print("Error: Internal file is not a valid .nessus file.")
        else:
            print(f"Processing Nessus File: {args.internal}")
            internal_data = parse_nessus_file(args.internal)
            write_to_excel(internal_data, 'Internal Scan', workbook)
            write_port_table(args.internal, workbook, "Internal Port Table", is_external=False)
            extract_host_data(args.internal, "Internal Host Data", workbook)
            write_protocols_tab(args.internal, workbook)
            write_missing_critical_patches(internal_data, workbook)
            write_smb_signing_off(args.internal, workbook)
            write_unsupported_software(internal_data, workbook)
            write_processes_tab(args.internal, workbook)
            
    
    if args.osint:
        if not os.path.isfile(args.osint) or not args.osint.lower().endswith('.xlsx'):
            print(f"Error: OSINT report is not a valid .xlsx file: {args.osint}")
        else:
            import_osint_report(args.osint, workbook)
    
    if args.bloodhound:
        if os.path.isfile(args.bloodhound) and args.bloodhound.endswith('.zip'):
            parse_bloodhound_zip(args.bloodhound, workbook)
        else:
            print("Error: Provided BloodHound file is not a valid .zip file.")

    if args.attackforge:
        if os.path.isfile(args.attackforge) and args.attackforge.endswith('.customization'):
            run_external = True
            run_internal = True
            append_customization_data(args.attackforge, workbook, use_external=run_external, use_internal=run_internal)
        else:
            print("Error: Provided AttackForge file is not a valid .customization file.")
            
    if args.combine:
        input_dir = args.combine
        output_file = args.output or "combined.nessus"

        if not os.path.isdir(input_dir):
            print(f"Error: Input directory '{input_dir}' does not exist.")
        else:
            combine_nessus_files(input_dir, output_file)
            print(f"Successfully merged .nessus files into: {output_file}")
            args.internal = output_file
    
    
    apply_workbook_styling(workbook)
    
    try:
        workbook.save(args.output)
        print(f"Report saved successfully: {args.output}")
    except Exception as e:
        print(f"Error saving report: {e}")

def main():
    args = parse_arguments()
    print(f"Arguments received: {args}")
    workbook = openpyxl.Workbook()
    workbook.remove(workbook.active)
    process_files(args, workbook)

if __name__ == "__main__":
    print(display_banner("banner.txt"))
    main()
