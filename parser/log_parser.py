import re
import requests
import urllib.parse

ANALYZE_URL = "http://127.0.0.1:8000/analyze"
LOG_PATTERN = re.compile(r'(GET|POST)\s+(.*?)\s+HTTP')

def parse_and_send(line, source_ip="127.0.0.1"):
    match = LOG_PATTERN.search(line)
    if match:
        method = match.group(1).lower() 
        path = match.group(2).lower()
        
        decoded_path = urllib.parse.unquote(path)
        
        print(f"[DEBUG-PARSER] MATCHED! Sending {method.upper()} request to: {decoded_path}")
        
        event = {
            "event": "web_request",
            "method": method,           
            "url": path,
            "path": path,
            "query_decoded": decoded_path,
            "source_ip": source_ip
        }
        try:
            requests.post(ANALYZE_URL, json={"events": [event]}, timeout=2)
        except:
            print("[DEBUG-PARSER] ERROR: Could not connect to API on port 8000. Is it running?")