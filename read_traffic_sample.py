import json

def read_file(path):
    for encoding in ['utf-8', 'utf-16', 'utf-16-le', 'cp1252']:
        try:
            with open(path, 'r', encoding=encoding) as f:
                return f.read()
        except:
            continue
    return None

content = read_file('out_traffic.json')
if content:
    try:
        data = json.loads(content)
        print(f"Data type: {type(data)}")
        if isinstance(data, list):
            print(f"Count: {len(data)}")
            print("First item keys:", data[0].keys())
            print("First item 'app':", data[0].get('app'))
            print("First item 'rcvdbyte':", data[0].get('rcvdbyte'))
            print("First item 'sentbyte':", data[0].get('sentbyte'))
        elif isinstance(data, dict):
             print("Keys:", data.keys())
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        print("Raw start:", content[:200])
else:
    print("Could not read file.")
