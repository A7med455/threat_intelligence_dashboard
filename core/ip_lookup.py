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
        "maxAgeInDays": 365
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
            print(f"✅ API Success: {ip} - Score: {result['score']} - Risk: {result['risk']}")
            return result
        
        else:
            #website gave an error
            print(f"❌ API Error: Status code {response.status_code} for {ip}")
            return None
    except Exception as e:
        print(f"❌ API Exception: {e}")
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
                print(f"📁 Using backup data for {ip} - Score: {item['score']}")
                return item
        
        # FIXED: If IP not found, create a proper response instead of returning random IP
        print(f"⚠️ IP {ip} not found in sample data. Creating default response.")
        return {
            "ip": ip,
            "score": 0,
            "risk": "Unknown",
            "country": "Unknown",
            "isp": "Unknown",
            "reports": 0,
            "last_reported": "Never",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "note": "IP not in database"
        }
    
    except Exception as e:
        print(f"❌ Cannot open sample_data.json: {e}")
        return None

#tries internet first, if it fails uses the backup file instead
def check_ip(ip):
    print(f"\n🔍 Looking up: {ip}")
    #first try internet
    result = check_from_internet(ip)
    
    #if internet failed, use backup file
    if result is None:
        print("⚠️ No internet/API failed. Using backup file.")
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
    #only save if Dangerous or High Risk
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
    
    print(f"🚨 FLAGGED: {result['ip']} is {risk}!")

# Alias for dashboard.py instead of check_ip
lookup_ip = check_ip