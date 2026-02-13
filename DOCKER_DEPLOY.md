# Instruções de Deploy com Docker

## Configuração Inicial

### 1. Configurar Banco de Dados

Você tem duas opções:

#### Opção A: SQL Server Externo (Recomendado para Produção)

1. Certifique-se de que o SQL Server está acessível da rede Docker
2. O usuário SQL Server precisa ter permissão `CREATE DATABASE`
3. Anote as credenciais:
   - Host/IP do SQL Server
   - Porta (geralmente 1433)
   - Usuário
   - Senha

#### Opção B: PostgreSQL em Docker

1. Descomente a seção `db` no `docker-compose.yml`
2. Descomente o volume `postgres_data`
3. Configure a senha em `.env`:
   ```
   DB_PASSWORD=sua_senha_segura
   ```

### 2. Build e Start

```bash
# Build das imagens
docker-compose build

# Iniciar os serviços
docker-compose up -d

# Ver logs
docker-compose logs -f web
```

### 3. Acessar o Setup Wizard

1. Acesse: `http://localhost:8000/setup/`
2. Siga o wizard para configurar o banco de dados
3. Crie a conta de administrador

### 4. Executar Migrations (se necessário)

```bash
docker-compose exec web python manage.py migrate
```

### 5. Criar Superuser (alternativa ao wizard)

```bash
docker-compose exec web python manage.py createsuperuser
```

## Comandos Úteis

```bash
# Parar os serviços
docker-compose down

# Rebuild após mudanças no código
docker-compose up -d --build

# Ver logs de um serviço específico
docker-compose logs -f celery

# Executar comandos Django
docker-compose exec web python manage.py <comando>

# Acessar shell do container
docker-compose exec web bash

# Coletar arquivos estáticos
docker-compose exec web python manage.py collectstatic --noinput
```

## Conectar ao SQL Server Externo

O container Docker consegue se conectar ao SQL Server externo usando:

- **Host:** IP ou hostname do SQL Server (acessível da rede Docker)
- **Porta:** 1433 (padrão)
- **Driver:** ODBC Driver 17 for SQL Server (já incluído no container)

**Exemplo de configuração no wizard:**
- Host: `192.168.1.100` (IP do SQL Server)
- Porta: `1433`
- Database: `VPN_SIEM`
- Usuário: `sa` ou outro usuário com permissões
- Senha: sua senha

## Troubleshooting

### Container não conecta ao SQL Server

1. Verifique se o SQL Server aceita conexões remotas
2. Verifique firewall (porta 1433 aberta)
3. Teste conectividade:
   ```bash
   docker-compose exec web ping <ip_sql_server>
   ```

### Erro de permissão no SQL Server

O usuário precisa ter:
```sql
GRANT CREATE DATABASE TO [usuario];
```

### Logs de erro

```bash
docker-compose logs -f web
```
