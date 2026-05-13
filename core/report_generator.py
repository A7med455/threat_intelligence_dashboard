import csv
import json
import os
from datetime import datetime
def _timestamp()-> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
def _safe_filename(ip: str) -> str:
    return ip.replace(".", "_")
def _ensure_dir(path:str)-> None:
        os.makedirs(path,exist_ok=True)
def generate_txt_report(ip_data: dict, output_dir: str = "reports") -> str:
     _ensure_dir(output_dir)
     ip =ip_data.get("ip","unknown_ip")
     score =ip_data.get("score","N/A")
     country =ip_data.get("country","N/A")
     isp =ip_data.get("isp","N/A")
     reports = ip_data.get("reports","N/A")
     risk =ip_data.get("risk_level","N/A")
     rec =ip_data.get("recommendation","N/A")
     content = f"""
========================================
   THREAT INTELLIGENCE REPORT
========================================
Generated : {_timestamp()}
----------------------------------------
IP Address        : {ip}
Country           : {country}
ISP               : {isp}
Abuse Score       : {score} / 100
Total Reports     : {reports}
Risk Level        : {risk}
----------------------------------------
RECOMMENDATION:
{rec}
========================================
"""
     filename = f"report_{_safe_filename(ip)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
     filepath = os.path.join(output_dir, filename)
     with open(filepath, "w",encoding="utf-8") as f:
          f.write(content.strip())
          print(f"[ReportGenerator] TXT report saved → {filepath}")
          return filepath
def generate_csv_report(ip_list:list[dict], output_dir:str ="reports")-> str:
        _ensure_dir(output_dir)
        fieldnames = ["ip","score","country","isp","reports","risk_level","recommendation"]
        filename   = f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath   = os.path.join(output_dir, filename)
        with open(filepath,"w",newline="",encoding="utf-8") as f:
            writer = csv.DictWriter(f,fieldnames=fieldnames,extrasaction="ignore")
            writer.writeheader()
            for entry in ip_list:
                writer.writerow(entry)
        print(f"[ReportGenerator] CSV report generated -> {filepath}")
        return filepath
def generate_json_report(ip_data:dict, output_dir:str ="reports")-> str:
    _ensure_dir(output_dir)
    ip =ip_data.get("ip","unknown_ip")
    filename = f"report_{_safe_filename(ip)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(output_dir, filename)
    payload = {
         "generated_at":_timestamp(),
         "data": ip_data
    }
    with open(filepath,"w",encoding="utf-8") as f:
        json.dump(payload,f,indent=4)
    print(f"[ReportGenerator] JSON report generated -> {filepath}")
    return filepath
def save_full_report(ip_data:dict, output_dir:str ="reports")-> str:
   txt_path = generate_txt_report(ip_data, output_dir)
   json_path = generate_json_report(ip_data, output_dir)
   return{
         "txt": txt_path,
         "json": json_path
   }      