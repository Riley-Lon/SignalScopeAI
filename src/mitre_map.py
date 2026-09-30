def map_mitre(reason_text: str) -> str:
    text = reason_text.lower()

    if "failed login" in text:
        return "T1110 - Brute Force"
    if "powershell" in text:
        return "T1059.001 - PowerShell"
    if "encoded command" in text:
        return "T1027 - Obfuscated Files or Information"
    if "outbound network connection" in text:
        return "T1041 - Exfiltration Over C2 Channel"

    return "Unknown"