from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Alignment

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
                if row_count == 0:
                    # This is the header row
                    for col, header in enumerate(row, start=1):
                        cell = target_sheet.cell(row=1, column=col, value=header)
                        cell.font = Font(bold=True)
                        cell.fill = PatternFill(start_color="E0E0E0", end_color="E0E0E0", fill_type="solid")
                        cell.alignment = Alignment(horizontal="left", vertical="bottom", wrap_text=True)
                else:
                    target_sheet.append(row)
                row_count += 1

            # Auto-adjust column widths
            for column in target_sheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if cell.value:
                            max_length = max(max_length, len(str(cell.value)))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)  # Cap width at 50
                target_sheet.column_dimensions[column_letter].width = adjusted_width

            print(f"Imported sheet: {sheet_name} as {new_sheet_name} with {row_count} rows.")

        print(f"Successfully imported OSINT report: {osint_file}")

    except Exception as e:
        print(f"Error importing OSINT report: {e}")
    
    pass
