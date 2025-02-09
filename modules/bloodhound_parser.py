import json
import os
import zipfile


def get_domain_admins(groups, users):
    # Create a lookup table for users by their ObjectIdentifier
    user_lookup = {
        user['ObjectIdentifier']: user.get('Properties', {})
        for user in users if isinstance(user, dict) and 'ObjectIdentifier' in user
    }

    # Find the 'Domain Admins' group
    domain_admin_group = next(
        (group for group in groups if group.get('Properties', {}).get('samaccountname', '') == 'Domain Admins'),
        None
    )

    if not domain_admin_group:
        print("Domain Admins group not found in the file.")
        return []

    # Find all members of the 'Domain Admins' group
    domain_admins = []
    for member in domain_admin_group.get('Members', []):
        object_id = member.get('ObjectIdentifier')
        object_type = member.get('ObjectType')

        # Match only users (ignore other object types)
        if object_type == 'User' and object_id in user_lookup:
            user_props = user_lookup[object_id]  # Get the Properties dictionary for the user

            # Validate user_props is a dictionary
            if not isinstance(user_props, dict):
                print(f"Invalid user_props for ObjectIdentifier {object_id}: {user_props}")
                continue

            domain_admins.append({
                'ObjectIdentifier': object_id,
                'displayname': user_props.get('displayname', 'Unknown'),
                'samaccountname': user_props.get('samaccountname', 'Unknown'),
                'enabled': user_props.get('enabled', False)
            })

    return domain_admins

def load_detection_rules(json_path):
    with open(json_path, 'r') as f:
        rules = json.load(f)

    # Convert filter and extract strings to executable functions
    for rule_name, rule in rules.items():
        rule['filter'] = eval(rule['filter'])  # Convert filter to a lambda function
        rule['extract'] = [eval(extract) for extract in rule['extract']]  # Convert each extract to a function

    return rules

def is_valid_zip(file_path):
    """Check if the provided file path is a valid .zip file."""
    return os.path.isfile(file_path) and file_path.endswith('.zip')

def parse_bloodhound_zip(zip_path, workbook):
    if not is_valid_zip(zip_path):
        print(f"Error: {zip_path} is not a valid .zip file.")
        return

    detection_rules = load_detection_rules('detection_rules.json')

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            groups = None
            users = None

            for file_name in zip_file.namelist():
                if "groups.json" in file_name.lower():
                    with zip_file.open(file_name) as f:
                        groups = json.load(f).get('data', [])

                if "users.json" in file_name.lower():
                    with zip_file.open(file_name) as f:
                        users = json.load(f).get('data', [])

            if groups and users:
                # Use the get_domain_admins helper function to extract domain admins
                domain_admins = get_domain_admins(groups, users)

                # Create a sheet for domain admins
                if domain_admins:
                    print("Creating sheet: Domain Admins")
                    ws = workbook.create_sheet(title="Domain Admins")
                    ws.append(["ObjectIdentifier SID","SAM Account Name","Enabled","Display Name"])
                    for admin in domain_admins:
                        ws.append(
                            [admin['ObjectIdentifier'], 
                             admin['samaccountname'],
                             admin['enabled'],
                             admin['displayname']
                            ])
                else:
                    print("No domain admins found.")
            else:
                print("Groups or users data missing in the BloodHound file.")

            # Process additional detection rules
            for file_name in zip_file.namelist():
                if "users.json" in file_name.lower():
                    with zip_file.open(file_name) as f:
                        data = json.load(f)

                        # Process each detection rule
                        for sheet_name, rule in detection_rules.items():
                            rows = []
                            for user in data.get('data', []):
                                try:
                                    if rule['filter'](user):
                                        rows.append([func(user) for func in rule['extract']])
                                except KeyError as e:
                                    print(f"Missing key {e} in user data.")
                                    continue

                            if rows:
                                print(f"Creating sheet: {sheet_name}")
                                ws = workbook.create_sheet(title=sheet_name)
                                ws.append(rule['headers'])
                                for row in rows:
                                    ws.append(row)

    except Exception as e:
        print(f"Error processing BloodHound file: {e}")

    # Ensure at least one sheet is visible
    if not workbook.sheetnames:
        print("Error: At least one sheet must be visible. No data was written.")
    pass