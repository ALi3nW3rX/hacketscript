from openpyxl import load_workbook


def import_osint_report(osint_file, workbook):
    try:
        osint_workbook = load_workbook(osint_file)

        for sheet_name in osint_workbook.sheetnames:
            osint_sheet = osint_workbook[sheet_name]

            # Append "OSINT - " to the sheet name and ensure no duplicates
            base_name = f"OSINT - {sheet_name}"  # Prefix sheet name with "OSINT -"
            new_sheet_name = base_name
            suffix = 1

            while new_sheet_name in workbook.sheetnames:
                new_sheet_name = f"{base_name}_{suffix}"  # Add a numerical suffix for duplicates
                suffix += 1

            # Create a new sheet in the target workbook
            target_sheet = workbook.create_sheet(title=new_sheet_name)

            # Copy data from OSINT sheet to the new sheet
            row_count = 0
            for row in osint_sheet.iter_rows(values_only=True):
                target_sheet.append(row)
                row_count += 1

            print(f"Imported sheet: {sheet_name} as {new_sheet_name} with {row_count} rows.")

        print(f"Successfully imported OSINT report: {osint_file}")

    except Exception as e:
        print(f"Error importing OSINT report: {e}")
        
    pass