def display_banner(banner_file):

    try:
        with open(banner_file, 'r', encoding='utf-8') as file:
            banner = file.read()
            print(banner)
    except Exception as e:
        print(f"Error: Unable to load banner from {banner_file}. {e}")
    
    pass