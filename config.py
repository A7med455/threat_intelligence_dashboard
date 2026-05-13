
API_KEY = "ece5d12aba0dd3aa54710975e38fef5cc42c1f4e90c108b2d3603c849af33be68844e5aa6cb13da7"

#we send request to this URL to check IP Address using our API Key
API_URL = "https://api.abuseipdb.com/api/v2/check"

#score 75 and above means this IP is extremely dangerous
Dangerous_Threat = 75
#score 50-74 means high risk
High_Threat = 50
#score 25-49 means suspicious activity
Suspicious_Threat = 25
#score 1-24 means low risk
Low_Threat = 1
#score 0 means completely safe
Safe = 0
#maxiumum number of search history entries 
Max_History = 100
#how many seconds to wait for API response before giving up (current 10 sec)
TIMEOUT = 10