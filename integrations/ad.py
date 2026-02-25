from ldap3 import Server, Connection, ALL
from .models import ActiveDirectoryConfig
import json
import logging

logger = logging.getLogger(__name__)

# Tenta importar redis para o cache
try:
    import redis
    redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
except:
    redis_client = None

class ActiveDirectoryClient:
    def __init__(self):
        self.config = ActiveDirectoryConfig.load()

    def get_connection(self):
        if not self.config.server:
            return None
            
        server = Server(
            self.config.server, 
            port=self.config.port, 
            use_ssl=self.config.use_ssl,
            get_info=ALL
        )
        # Se for necessário autenticação
        if self.config.bind_user and self.config.bind_password:
            conn = Connection(
                server, 
                user=self.config.bind_user, 
                password=self.config.bind_password,
                auto_bind=True
            )
        else:
            conn = Connection(server, auto_bind=True)
            
        return conn

    def get_user_info(self, username):
        """
        Busca informações do usuário no AD com cache no Redis (1 hora).
        """
        if not username:
            return None

        # 1. Tentar Cache
        cache_key = f"ad_user:{username.lower()}"
        if redis_client:
            try:
                cached = redis_client.get(cache_key)
                if cached:
                    return json.loads(cached)
            except:
                pass

        # 2. Consultar AD
        conn = self.get_connection()
        if not conn:
            return None

        search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
        
        try:
            conn.search(
                search_base=self.config.base_dn,
                search_filter=search_filter,
                attributes=['mail', 'department', 'displayName', 'title']
            )
            
            res = None
            if conn.entries:
                entry = conn.entries[0]
                res = {
                    'email': str(entry.mail) if hasattr(entry, 'mail') and entry.mail else None,
                    'department': str(entry.department) if hasattr(entry, 'department') and entry.department else None,
                    'display_name': str(entry.displayName) if hasattr(entry, 'displayName') and entry.displayName else None,
                    'title': str(entry.title) if hasattr(entry, 'title') and entry.title else None
                }
            
            # 3. Salvar no Cache (mesmo se for None, para evitar negativas repetitivas, por 10min)
            if redis_client:
                try:
                    expiry = 3600 if res else 600
                    redis_client.setex(cache_key, expiry, json.dumps(res))
                except:
                    pass
            
            return res
        except Exception as e:
            logger.error(f"Erro ao consultar AD para {username}: {e}")
            return None
