import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://10.10.1.52/jsonrpc"
headers = {
    "Content-Type": "application/json"
}
payload = {
    "id": 1,
    "jsonrpc": "2.0",
    "method": "add",
    "params": [
      {
        "apiver": 3,
        "url": "/log/view/adom/root/log_type/event",
        "logtype": "event",
        "time-order": "desc",
        "time-range": { "start": "2026-02-05T00:00:00", "end": "2026-02-05T23:59:59" },
        "filter": 'subtype=="vpn"'
      }
    ],
    "session": "g7pswamouf7yjscrgiypioykzcucdq3n"
}

print("Enviando requisição manual...")
try:
    response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
    print(f"Status Code: {response.status_code}")
    print("Response JSON:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Erro: {e}")
