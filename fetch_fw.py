import urllib.request
import json

url = "http://localhost:8000/security/devices/api/"
req = urllib.request.Request(url)
# No auth headers? The view might not have @login_required, or it might redirect.
try:
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        for d in data:
            if "FWMTZ03" in d.get("hostname", ""):
                print(json.dumps(d, indent=2))
except Exception as e:
    print(f"Failed to fetch API: {e}")
