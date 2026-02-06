from ldap3 import Server, Connection, SUBTREE, ALL
from .models import ActiveDirectoryConfig

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
        Busca informações do usuário no AD.
        """
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
            
            if conn.entries:
                entry = conn.entries[0]
                return {
                    'email': str(entry.mail) if entry.mail else None,
                    'department': str(entry.department) if entry.department else None,
                    'display_name': str(entry.displayName) if entry.displayName else None,
                    'title': str(entry.title) if entry.title else None
                }
            return None
        except Exception as e:
            print(f"Erro ao consultar AD: {e}")
            return None
