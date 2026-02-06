import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://10.10.1.52/jsonrpc"
headers = {
    "Content-Type": "application/json"
}
payload = {
    "method": "get",
    "params": [
        {
            "url": "/sys/adom"
        }
    ],
    "session": "g7pswamouf7yjscrgiypioykzcucdq3n",
    "id": 1
}

print("Tentando listar ADOMs...")
try:
    response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
    print(f"Status Code: {response.status_code}")
    print("Response JSON:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Erro: {e}")
