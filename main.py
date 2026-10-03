from datetime import datetime


def analyze_alert(source_ip, username, event_type):
    """
    Analyze a security event and assign a severity level.
    """

    if event_type == "Multiple Failed Logins":
        severity = "HIGH"
        recommendation = "Investigate for possible brute-force or password-spray activity."

    elif event_type == "Successful Login":
        severity = "LOW"
        recommendation = "Review whether the login matches the user's normal activity."

    elif event_type == "Malware Detected":
        severity = "CRITICAL"
        recommendation = "Isolate the endpoint and begin incident response."

    elif event_type == "Suspicious PowerShell":
        severity = "HIGH"
        recommendation = "Investigate the PowerShell command and parent process."

    elif event_type == "Impossible Travel":
        severity = "HIGH"
        recommendation = "Investigate whether the account was compromised."

    else:
        severity = "MEDIUM"
        recommendation = "Perform additional investigation."

    print("\n========== SOC ALERT ==========")
    print(f"Time          : {datetime.now()}")
    print(f"Source IP     : {source_ip}")
    print(f"Username      : {username}")
    print(f"Event Type    : {event_type}")
    print(f"Severity      : {severity}")
    print(f"Recommendation: {recommendation}")
    print("===============================\n")


def main():

    print("SOC Alert Analyzer")
    print("------------------")

    analyze_alert(
        "192.168.1.25",
        "jsmith",
        "Multiple Failed Logins"
    )

    analyze_alert(
        "192.168.1.50",
        "admin",
        "Malware Detected"
    )

    analyze_alert(
        "192.168.1.100",
        "administrator",
        "Suspicious PowerShell"
    )
    
    analyze_alert(
        "10.10.20.15",
        "jsmith",
        "Impossible Travel"
    )


if __name__ == "__main__":
    main()
