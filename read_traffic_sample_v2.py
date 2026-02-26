import json
import re

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
    # Localizar o primeiro { que parece ser o início do JSON
    match = re.search(r'\{.*\}', content, re.DOTALL)
    if match:
        json_str = match.group(0)
        try:
            data = json.loads(json_str)
            # A estrutura parece ser { "result": { "data": [...] } } ou similar
            results = []
            if 'result' in data:
                res = data['result']
                if isinstance(res, list) and len(res) > 0 and 'data' in res[0]:
                    results = res[0]['data']
                elif isinstance(res, dict) and 'data' in res:
                    results = res['data']
            
            if results:
                print(f"Encontrados {len(results)} registros de tráfego.")
                sample = results[0]
                print("Campos disponíveis:", sorted(sample.keys()))
                print(f"Amostra - App: {sample.get('app')}, Cat: {sample.get('appcat')}, Risk: {sample.get('apprisk')}")
                print(f"Amostra - In: {sample.get('rcvdbyte')}, Out: {sample.get('sentbyte')}")
            else:
                print("Nenhum dado encontrado no JSON.")
        except Exception as e:
            print(f"Erro ao parsear JSON extraído: {e}")
            print("Início da string extraída:", json_str[:200])
    else:
        print("Nenhum bloco JSON encontrado no arquivo.")
else:
    print("Could not read file.")
