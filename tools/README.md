# Organized Utility and Backfill Tools

Este diretório contém os scripts de reparo, backfill, simulação e diagnóstico que anteriormente acumulavam-se na raiz do projeto. Eles foram organizados em subpastas para reduzir o débito técnico e manter a raiz limpa.

## Estrutura de Pastas

- **`database/`**: Scripts de diagnósticos, limpezas e ajustes no banco de dados principal.
- **`backfills/`**: Utilitários para reprocessamento de logs históricos e sincronizações retroativas.
- **`simulations/`**: Scripts para simular ataques e eventos para testes de segurança.
- **`scrapers/`**: Ferramentas auxiliares de coleta, monitoramento de hosts e análise rápida de logs.
- **`geoip/`**: Utilitários de correção de geolocalização IP e atualização do banco do GeoIP.
- **`system/`**: Scripts de inicialização do sistema, mocks e manutenção administrativa.
- **`temp_web/`**: Arquivos temporários HTML e assets antigos.

## Como Executar os Scripts

Muitos destes scripts dependem de modelos ou configurações do Django. Para executá-los corretamente mantendo a capacidade do Django de resolver importações, defina a variável de ambiente `PYTHONPATH` para a raiz do projeto.

### Exemplo (PowerShell):
```powershell
$env:PYTHONPATH="."
python tools/backfills/run_backfill.py
```

### Exemplo (Linux / Bash):
```bash
PYTHONPATH=. python tools/backfills/run_backfill.py
```
