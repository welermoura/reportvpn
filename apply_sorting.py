
import os

file_path = r'c:\Users\welerms\Projeto-teste\dashboard\templates\dashboard\vpn_react.html'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Add handleSort and getSortIcon after currentTime state
target_hooks = "const [currentTime, setCurrentTime] = useState(new Date());"
replacement_hooks = """const [currentTime, setCurrentTime] = useState(new Date());

        const handleSort = (field) => {
            setFilters(prev => {
                const isCurrent = prev.ordering === field || prev.ordering === `-${field}`;
                if (!isCurrent) return { ...prev, ordering: `-${field}` };
                return { ...prev, ordering: prev.ordering.startsWith('-') ? field : `-${field}` };
            });
        };

        const getSortIcon = (field) => {
            if (filters.ordering === field) return ' ▴';
            if (filters.ordering === `-${field}`) return ' ▾';
            return '';
        };"""

if target_hooks in content and "handleSort" not in content:
    content = content.replace(target_hooks, replacement_hooks)
    print("Added sort hooks")

# Update thead block
target_thead = """                                    <th style={{ width: '220px' }}>Usuário</th>
                                    <th>Cargo</th>
                                    <th>Depto</th>
                                    <th style={{ textAlign: 'center' }}>Qtd Conexões</th>
                                    <th>Acesso</th>
                                    <th>Origem</th>
                                    <th>Cidade</th>
                                    <th>País</th>
                                    <th>Volume</th>
                                    <th>Duração</th>
                                    <th>Detalhes</th>"""

replacement_thead = """                                    <th style={{ width: '220px', cursor: 'pointer' }} onClick={() => handleSort('user')}>Usuário {getSortIcon('user')}</th>
                                    <th style={{ cursor: 'pointer' }} onClick={() => handleSort('title')}>Cargo {getSortIcon('title')}</th>
                                    <th style={{ cursor: 'pointer' }} onClick={() => handleSort('dept')}>Depto {getSortIcon('dept')}</th>
                                    <th style={{ textAlign: 'center', cursor: 'pointer' }} onClick={() => handleSort('connections')}>Qtd Conexões {getSortIcon('connections')}</th>
                                    <th style={{ cursor: 'pointer' }} onClick={() => handleSort('last_connection')}>Acesso {getSortIcon('last_connection')}</th>
                                    <th>Origem</th>
                                    <th>Cidade</th>
                                    <th>País</th>
                                    <th style={{ cursor: 'pointer' }} onClick={() => handleSort('volume')}>Volume {getSortIcon('volume')}</th>
                                    <th style={{ cursor: 'pointer' }} onClick={() => handleSort('duration')}>Duração {getSortIcon('duration')}</th>
                                    <th>Detalhes</th>"""

if target_thead in content:
    content = content.replace(target_thead, replacement_thead)
    print("Replaced thead")
else:
    print("Thead target not found exactly - checking for minor variations")
    # Fallback to a simpler replace if exact block fails
    content = content.replace("<th style={{ width: '220px' }}>Usuário</th>", "<th style={{ width: '220px', cursor: 'pointer' }} onClick={() => handleSort('user')}>Usuário {getSortIcon('user')}</th>")
    content = content.replace("<th>Cargo</th>", "<th style={{ cursor: 'pointer' }} onClick={() => handleSort('title')}>Cargo {getSortIcon('title')}</th>")
    content = content.replace("<th>Depto</th>", "<th style={{ cursor: 'pointer' }} onClick={() => handleSort('dept')}>Depto {getSortIcon('dept')}</th>")
    content = content.replace("<th style={{ textAlign: 'center' }}>Qtd Conexões</th>", "<th style={{ textAlign: 'center', cursor: 'pointer' }} onClick={() => handleSort('connections')}>Qtd Conexões {getSortIcon('connections')}</th>")
    content = content.replace("<th>Acesso</th>", "<th style={{ cursor: 'pointer' }} onClick={() => handleSort('last_connection')}>Acesso {getSortIcon('last_connection')}</th>")
    content = content.replace("<th>Volume</th>", "<th style={{ cursor: 'pointer' }} onClick={() => handleSort('volume')}>Volume {getSortIcon('volume')}</th>")
    content = content.replace("<th>Duração</th>", "<th style={{ cursor: 'pointer' }} onClick={() => handleSort('duration')}>Duração {getSortIcon('duration')}</th>")

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
