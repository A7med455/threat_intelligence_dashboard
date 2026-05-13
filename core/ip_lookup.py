import sys
import os

PROJECT_FOLDER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_FOLDER)

# Build correct paths to data files
SAMPLE_FILE = os.path.join(PROJECT_FOLDER, "data", "sample_data.json")
HISTORY_FILE = os.path.join(PROJECT_FOLDER, "data", "history.json")
FLAGGED_FILE = os.path.join(PROJECT_FOLDER, "data", "flagged_ips.json")

import requests
import json
from datetime import datetime
from config import API_KEY, API_URL, TIMEOUT, Max_History
from config import Dangerous_Threat, High_Threat, Suspicious_Threat, Low_Threat, Safe
#get the risk level based on the score (0-100)
def get_risk(score):
    if score >= Dangerous_Threat:
        return "Dangerous"
    elif score >= High_Threat:
        return "High Risk"
    elif score >= Suspicious_Threat:
        return "Suspicious"
    elif score >= Low_Threat:
        return "Low Risk"
    else:
        return "Safe"

#ask AbuseIPDB about an IP using the internet
def check_from_internet(ip):
    #header with key to be sent in the request so the API knows who we are
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    #params are the questions we ask the API (which IP, how far back to look)
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    #send request to the website
    try:
        response = requests.get(
            API_URL,
            headers=headers,
            params=params,
            timeout=TIMEOUT
        )
        #if ok read the data
        if response.status_code == 200:
            data = response.json()
            ip_info = data["data"]
            
            #dictionary for the result
            result = {
                "ip": ip_info.get("ipAddress", ip),
                "score": ip_info.get("abuseConfidenceScore", 0),
                "risk": get_risk(ip_info.get("abuseConfidenceScore", 0)),
                "country": ip_info.get("countryName", "Unknown"),
                "isp": ip_info.get("isp", "Unknown"),
                "reports": ip_info.get("totalReports", 0),
                "last_reported": ip_info.get("lastReportedAt", "Never"),
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            return result
        
        else:
            #website gave an error
            return None
    except:
        #no internet or something went wrong
        return None

#check the IP from the sample data file (backup plan)
def check_from_file(ip):
    try:
        #open the local backup file
        with open(SAMPLE_FILE, "r") as f:
            all_ips = json.load(f)
        #search for the IP in the list
        for item in all_ips:
            if item["ip"] == ip:
                item["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                item["note"] = "offline data"
                return item
        
        #if IP not found return first one as example
        return all_ips[0]
    
    except:
        print("Cannot open sample_data.json")
        return None

#tries internet first, if it fails uses the backup file instead
def check_ip(ip):
    #first try internet
    result = check_from_internet(ip)
    
    #if internet failed, use backup file
    if result is None:
        print("No internet. Using backup file.")
        result = check_from_file(ip)

    return result

#save result to history so we can see past searches
def save_history(result):
    try:
        #read old history
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)
    except:
        #file doesn't exist, start empty
        history = []
    
    #add new result at top
    history.insert(0, result)
    
    #keep only last Max_History entries to keep file size small
    if len(history) > Max_History:
        history = history[:Max_History]
    
    #save back to file
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

#save dangerous IP to flagged list
def save_dangerous(result):
    #only save if High risk
    risk = result.get("risk")
    if risk not in ["Dangerous", "High Risk"]:
        return
    #add flag info
    result["flagged_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["reason"] = f"Score: {result['score']} - {risk}"
    
    try:
        #read old flagged IPs
        with open(FLAGGED_FILE, "r") as f:
            flagged = json.load(f)
    except:
        #file doesn't exist, start empty
        flagged = []
    #check if already flagged so we don't add duplicates
    for item in flagged:
        if item["ip"] == result["ip"]:
            print("Already flagged before.")
            return
    #add to list
    flagged.insert(0, result)
    #save back
    with open(FLAGGED_FILE, "w") as f:
        json.dump(flagged, f, indent=2)
    
    print(f"FLAGGED: {result['ip']} is dangerous!")
# Alias for dashboard.py instead of check_ip
lookup_ip = check_ip


"""
if __name__ == "__main__":
    
    print("=" * 50)
    print("TESTING IP LOOKUP")
    print("=" * 50)
    
    # Test 1: Safe IP
    print("\n1. Checking Google DNS (8.8.8.8)...")
    result1 = check_ip("8.8.8.8")
    print(f"   IP: {result1['ip']}")
    print(f"   Score: {result1['score']}")
    print(f"   Risk: {result1['risk']}")
    print(f"   Country: {result1['country']}")
    save_history(result1)
    save_dangerous(result1)
    
    # Test 2: Dangerous IP
    print("\n2. Checking Bad IP (185.220.101.1)...")
    result2 = check_ip("185.220.101.1")
    print(f"   IP: {result2['ip']}")
    print(f"   Score: {result2['score']}")
    print(f"   Risk: {result2['risk']}")
    print(f"   Country: {result2['country']}")
    save_history(result2)
    save_dangerous(result2)
    
    print("\n" + "=" * 50)
    print("TEST COMPLETE")
    print("=" * 50)
"""