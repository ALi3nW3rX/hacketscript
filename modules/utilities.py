try:
    import ipaddress  # For detecting IPv6 if needed
except ImportError:
    ipaddress = None

# Mapping for severity levels
SEVERITY_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical"
}

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}



def colored_text(text, color="white"):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "white": "\033[97m",
        "reset": "\033[0m",
    }
    return f"{colors.get(color, colors['white'])}{text}{colors['reset']}"
pass

def bold_text(text):
    return f"\033[1m{text}\033[0m"
pass




