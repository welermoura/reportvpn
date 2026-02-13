"""Verify and fix index.html and ips.html split tags."""
import os

templates_dir = r'c:\Users\welerms\Projeto-teste\security_events\templates\security_events'

for fname in ['index.html', 'ips.html']:
    fpath = os.path.join(templates_dir, fname)
    with open(fpath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    changed = False
    i = 0
    while i < len(lines) - 1:
        line = lines[i]
        next_line = lines[i+1]
        
        # Detect: severity_display split across 2 lines
        if 'get_severity_display' in line and '}}' not in line.split('get_severity_display')[1]:
            # The }} is on the next line
            indent = '                                    ' if 'index' in fname else '                            '
            fixed = indent + '<td><span class="badge bg-{{ event.get_severity_color }}">{{ event.get_severity_display }}</span></td>\n'
            print(f"FIXING {fname}:{i+1}-{i+2}")
            print(f"  OLD L{i+1}: {line.rstrip()}")
            print(f"  OLD L{i+2}: {next_line.rstrip()}")
            lines[i] = fixed
            lines.pop(i+1)
            print(f"  NEW L{i+1}: {fixed.rstrip()}")
            changed = True
        elif 'get_severity_display' in next_line and '{{' not in next_line.split('get_severity_display')[0]:
            # {{ is on current line, value+}} on next line
            indent = '                                    ' if 'index' in fname else '                            '
            fixed = indent + '<td><span class="badge bg-{{ event.get_severity_color }}">{{ event.get_severity_display }}</span></td>\n'
            print(f"FIXING {fname}:{i+1}-{i+2}")
            print(f"  OLD L{i+1}: {line.rstrip()}")
            print(f"  OLD L{i+2}: {next_line.rstrip()}")
            lines[i] = fixed
            lines.pop(i+1)
            print(f"  NEW L{i+1}: {fixed.rstrip()}")
            changed = True
        i += 1
    
    if changed:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f"SAVED: {fname}")
    else:
        # Check if tags are already on single line
        content = ''.join(lines)
        if '{{ event.get_severity_display }}' in content:
            print(f"OK: {fname} - severity tag already on single line")
        else:
            print(f"WARNING: {fname} - could not find or fix severity tag!")
            # Show relevant lines
            for j, l in enumerate(lines):
                if 'severity' in l.lower():
                    print(f"  L{j+1}: {l.rstrip()}")

# Also verify webfilter.html
fpath = os.path.join(templates_dir, 'webfilter.html')
with open(fpath, 'r', encoding='utf-8') as f:
    content = f.read()
if '{{ event.action }}' in content:
    print(f"\nOK: webfilter.html - action tag on single line")
else:
    print(f"\nWARNING: webfilter.html - action tag not found!")

print("\nDone!")
