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

# CVSS v3.0 Severity Mapping Function
def get_cvss3_severity(score):
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "Informational"

# CVSS v2.0 Severity Mapping Function
def get_cvss2_severity(score):
    if score >= 10.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "Informational"

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




