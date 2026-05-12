import requests
import json
from datetime import datetime
from config import API_KEY, API_URL, TIMEOUT, High_Threat, Medium_Threat, Max_History

#get the risk level based on the score (0-100)
def get_risk(score):
    if score >= High_Threat:
        return "High"
    elif score >= Medium_Threat:
        return "Medium"
    else:
        return "Low"

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
        with open("data/sample_data.json", "r") as f:
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
        with open("data/history.json", "r") as f:
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
    with open("data/history.json", "w") as f:
        json.dump(history, f, indent=2)

#save dangerous IP to flagged list
def save_dangerous(result):
    #only save if High risk
    if result.get("risk") != "High":
        return
    #add flag info
    result["flagged_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["reason"] = f"Score: {result['score']}"
    
    try:
        #read old flagged IPs
        with open("data/flagged_ips.json", "r") as f:
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
    with open("data/flagged_ips.json", "w") as f:
        json.dump(flagged, f, indent=2)
    
    print(f"FLAGGED: {result['ip']} is dangerous!")
