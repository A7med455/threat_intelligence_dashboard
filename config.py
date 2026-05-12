
API_KEY = "Will generate an API Key later"

#we send request to this URL to check IP Address using our API Key
API_URL = "https://api.abuseipdb.com/api/v2/check"

#Score above 80 means ths ip is very dangerous (high risk)
High_Threat = 80
#score between 40-80 means moderate danger (medium risk)
Medium_Threat = 40
#means this ip is mostly safe (low risk)
Low_Threat = 0
#maxiumum number of search history entries 
Max_History = 100
#how many seconds to wait for API response before giving up (current 10 sec)
TIMEOUT = 10
#HTTP Header sent with every API Requet
#we use the key for authentication (to know who we are)
#"Accept": "application/json" tells server to return JSON format data
HEADERS = {
    "Key" : API_KEY,
    "Accept":"application/json"
}
