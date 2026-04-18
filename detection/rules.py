from collections import defaultdict

ATTACK_MAPPING = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "severity": "High"
    },
    "powershell_activity": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "severity": "Medium"
    },
    "account_discovery": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "severity": "Medium"
    }
}


def detect_brute_force(events, threshold=5):
    counter = defaultdict(int)
    alerts = []

    for event in events:
        if event.get("event") == "failed_login" and event.get("event_id") == "4625":
            key = (
                event.get("computer"),
                event.get("logon_type"),
                event.get("timestamp")[:16]
            )
            counter[key] += 1

    for (computer, logon_type, minute), count in counter.items():
        if count >= threshold:
            alerts.append({
                "alert_type": "brute_force",
                "severity": ATTACK_MAPPING["brute_force"]["severity"],
                "technique_id": ATTACK_MAPPING["brute_force"]["technique_id"],
                "technique_name": ATTACK_MAPPING["brute_force"]["technique_name"],
                "computer": computer,
                "logon_type": logon_type,
                "attempt_count": count,
                "minute": minute
            })

    return alerts


def detect_powershell_activity(events):
    alerts = []

    for event in events:
        if event.get("event") == "powershell_exec" and event.get("event_id") == "4104":
            command = event.get("command", "")

            alerts.append({
                "alert_type": "powershell_activity",
                "severity": ATTACK_MAPPING["powershell_activity"]["severity"],
                "technique_id": ATTACK_MAPPING["powershell_activity"]["technique_id"],
                "technique_name": ATTACK_MAPPING["powershell_activity"]["technique_name"],
                "user": event.get("user"),
                "computer": event.get("computer"),
                "command": command,
                "timestamp": event.get("timestamp")
            })

    return alerts


def detect_account_discovery(events):
    alerts = []

    discovery_keywords = ["Get-ChildItem", "Get-LocalUser", "net user", "whoami"]

    for event in events:
        if event.get("event") == "powershell_exec" and event.get("event_id") == "4104":
            command = event.get("command", "")
            if any(keyword.lower() in command.lower() for keyword in discovery_keywords):
                alerts.append({
                    "alert_type": "account_discovery",
                    "severity": ATTACK_MAPPING["account_discovery"]["severity"],
                    "technique_id": ATTACK_MAPPING["account_discovery"]["technique_id"],
                    "technique_name": ATTACK_MAPPING["account_discovery"]["technique_name"],
                    "user": event.get("user"),
                    "computer": event.get("computer"),
                    "command": command,
                    "timestamp": event.get("timestamp")
                })

    return alerts


def run_all_detections(events):
    alerts = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_powershell_activity(events))
    alerts.extend(detect_account_discovery(events))
    return alerts