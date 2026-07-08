
import os
import re

file_path = r'c:\Users\welerms\Projeto-teste\dashboard\templates\dashboard\vpn_react.html'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Update handleSort for intuitive behavior (Asc for text, Desc for numbers as default)
new_handle_sort = """const handleSort = (field) => {
            setFilters(prev => {
                const isCurrent = prev.ordering === field || prev.ordering === `-${field}`;
                if (!isCurrent) {
                    // Texto (user, title, dept) -> Começar com A-Z (asc)
                    // Números/Datas (connections, last_connection, volume, duration) -> Começar com Maior-Menor (desc)
                    const textFields = ['user', 'title', 'dept'];
                    const defaultOrder = textFields.includes(field) ? field : `-${field}`;
                    return { ...prev, ordering: defaultOrder };
                }
                // Alternar entre asc e desc if clicking same column
                return { ...prev, ordering: prev.ordering.startsWith('-') ? field : `-${field}` };
            });
        };"""

# Use regex to replace the old handleSort body
pattern = r'const handleSort = \(field\) => \{.*?\}\s*;'
content = re.sub(pattern, new_handle_sort, content, flags=re.DOTALL)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Updated frontend handleSort")
