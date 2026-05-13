import json
import os
from datetime import datetime

FLAGGED_IPS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "flagged_ips.json")
# any IP with score >= 75 is considered malicious
MALICIOUS_THRESHOLD = 75

# Load & Save flagged_ips.json
def _load_flagged():
    if not os.path.exists(FLAGGED_IPS_FILE):
        return []
    with open(FLAGGED_IPS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def _save_flagged(flagged_list):
    os.makedirs(os.path.dirname(FLAGGED_IPS_FILE), exist_ok=True)
    with open(FLAGGED_IPS_FILE, "w") as f:
        json.dump(flagged_list, f, indent=4)


def _get_severity(score):
    if score >= 95:
        return "EXTREME"
    elif score >= 85:
        return "CRITICAL"
    else:
        return "HIGH"


def is_malicious(abuse_score):
    return abuse_score >= MALICIOUS_THRESHOLD


def flag_ip(ip_data):
    score = ip_data.get("score", 0)

    if not is_malicious(score):
        return {
            "status": "skipped",
            "message": f"IP {ip_data.get('ip')} has score {score} — below threshold ({MALICIOUS_THRESHOLD}). Not flagged."
        }

    # IP is malicious — create alert record
    alert = {
        "ip": ip_data.get("ip", "Unknown"),
        "score": score,
        "country": ip_data.get("country", "Unknown"),
        "reports": ip_data.get("reports", 0),
        "isp": ip_data.get("isp", "Unknown"),
        "flagged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": _get_severity(score)
    }

    # Avoid duplicates
    flagged_list = _load_flagged()
    existing_ips = [entry.get("ip") for entry in flagged_list]

    if alert["ip"] in existing_ips:
        return {
            "status": "duplicate",
            "message": f"IP {alert['ip']} is already flagged.",
            "alert": alert
        }

    flagged_list.append(alert)
    _save_flagged(flagged_list)

    return {
        "status": "flagged",
        "message": f"IP {alert['ip']} flagged as {alert['severity']}.",
        "alert": alert
    }


def check_and_alert(ip_data):
    score = ip_data.get("score", 0)

    if is_malicious(score):
        result = flag_ip(ip_data)
        result["alert_triggered"] = True
    else:
        result = {
            "status": "clean",
            "message": f"IP {ip_data.get('ip')} is clean (score {score}).",
            "alert_triggered": False
        }

    return result


def get_all_flagged():
    return _load_flagged()


def clear_flagged():
    _save_flagged([])
    return {
        "status": "cleared",
        "message": "All flagged IPs have been removed."
    }


def remove_flag(ip):
    flagged_list = _load_flagged()
    new_list = [entry for entry in flagged_list if entry["ip"] != ip]

    if len(new_list) == len(flagged_list):
        return {"status": "not_found", "message": f"IP {ip} was not in the flagged list."}

    _save_flagged(new_list)
    return {"status": "removed", "message": f"IP {ip} has been removed from flagged list."}