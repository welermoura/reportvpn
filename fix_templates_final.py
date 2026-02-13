import os
import re

templates_dir = r'c:\Users\welerms\Projeto-teste\security_events\templates\security_events'

def fix_spaces_in_tags(content):
    # Fix {% if var==val %} or {% if var=='val' %} to {% if var == val %}
    # Handle both == and !=
    content = re.sub(r'\{%\s*if\s+([a-zA-Z0-9_\.]+)([=!]=)([a-zA-Z0-9_\.\']+)\s*%\}', r'{% if \1 \2 \3 %}', content)
    # Fix specific common cases if regex missed them
    content = content.replace('days==', 'days == ')
    content = content.replace("=='ips'", " == 'ips'")
    content = content.replace("=='antivirus'", " == 'antivirus'")
    content = content.replace("=='webfilter'", " == 'webfilter'")
    return content

def fix_split_tags(content):
    # Join {{ \n ... }}
    content = re.sub(r'\{\{\s*\n\s*', '{{ ', content)
    # Join ... \n }}
    content = re.sub(r'\s*\n\s*\}\}', ' }}', content)
    return content

for filename in ['index.html', 'ips.html', 'webfilter.html', 'antivirus.html']:
    filepath = os.path.join(templates_dir, filename)
    if not os.path.exists(filepath):
        continue
        
    print(f"Processing {filename}...")
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    new_content = fix_spaces_in_tags(content)
    new_content = fix_split_tags(new_content)
    
    if content != new_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Fixed {filename}")
    else:
        print(f"No changes for {filename}")

print("Done fixing local templates.")
