import os
import sys
import django
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from collections import defaultdict, deque

# Setup Django caso executado standalone
if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
    django.setup()

from integrations.models import ActiveDirectoryConfig
from security_events.models import ADUser, ADGroup, ADMemberOf, ADRiskSnapshot
from ldap3 import Server, Connection, SUBTREE, ALL

# Grupos Privilegiados comuns da Microsoft (base Radar AD)
PRIV_GROUP_CNS = {
    "domain admins": 100,
    "enterprise admins": 95,
    "schema admins": 90,
    "administrators": 85,
    "account operators": 70,
    "server operators": 70,
    "backup operators": 70,
    "print operators": 60,
    "group policy creator owners": 65,
    "dnsadmins": 65,
}

# 116444736000000000 é a diferenca de epoch entre 1601 (Windows) e 1970 (UNIX) em ticks de 100ns
WINDOWS_TICKS_EPOCH = 116444736000000000

def windows_filetime_to_datetime(filetime: str):
    try:
        ticks = int(filetime)
        if ticks <= 0: return None
        epoch_secs = (ticks - WINDOWS_TICKS_EPOCH) / 10000000.0
        return datetime.fromtimestamp(epoch_secs, tz=timezone.utc)
    except:
        return None

def is_account_disabled(uac_val):
    try:
        return bool(int(uac_val) & 0x0002)
    except:
        return False

# ----- HELPER FUNCS DO RADAR AD -----
def score_for_path(priv_weight, hops):
    hops = max(1, hops)
    return round(priv_weight / hops, 3)

def compute_impact_for_finding(priv_group_cn):
    priv = (priv_group_cn or "").lower()
    high_groups = {"domain admins", "enterprise admins", "schema admins", "administrators", "group policy creator owners"}
    if priv in high_groups:
        return "ALTO"
    return "MÉDIO"
    
def bfs_shortest_path_to_any_priv(start_dn, adj, priv_dns, max_depth=15):
    q = deque([start_dn])
    prev = {start_dn: None}
    depth = {start_dn: 0}

    while q:
        cur = q.popleft()
        d = depth[cur]
        if d > max_depth:
            continue

        if cur in priv_dns and cur != start_dn:
            path = []
            x = cur
            while x is not None:
                path.append(x)
                x = prev[x]
            path.reverse()
            return cur, path

        for nxt in adj.get(cur, []):
            if nxt not in prev:
                prev[nxt] = cur
                depth[nxt] = d + 1
                q.append(nxt)

    return None, None
# ------------------------------------

class RadarScanner:
    def __init__(self):
        self.config = ActiveDirectoryConfig.load()
        self.inactive_days = 90 # Configuravel no portal futuro
        self._sid_map = {} # Cache local
        self._group_dns = {}

    def get_connection(self):
        if not self.config.server:
            raise ValueError("O servidor Active Directory não está configurado. Vá em Painel > Integrações.")
            
        server = Server(
            self.config.server, 
            port=self.config.port, 
            use_ssl=self.config.use_ssl,
            get_info=ALL
        )
        
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

    def run_scan(self):
        print("[Radar AD] Iniciando varredura da postura de privilégios com algoritmo BFS...")
        conn = self.get_connection()

        # LIMPAR base anterior do Radar p/ refazer as fotos
        ADUser.objects.all().delete()
        ADGroup.objects.all().delete()
        ADMemberOf.objects.all().delete()

        # Dicionários na memória para BFS
        nodes_info = {} # dn -> {"type": "user"/"group", "id": dn, "name": ...}
        edges_mem = [] # {"src": dn, "dst": dn, "rel": "MEMBER_OF"}

        # ==================================
        # 1. OBTER E CRIAR OS GRUPOS 
        # ==================================
        print("[Radar AD] Coletando Grupos (com paginação)...")
        conn.search(
            search_base=self.config.base_dn,
            search_filter="(objectClass=group)",
            attributes=['cn', 'objectSid', 'distinguishedName', 'member'],
            paged_size=1000
        )
        
        for entry in conn.entries:
            cn = str(entry.cn)
            dn = str(entry.distinguishedName).lower()
            
            try: sid = entry.objectSid.value
            except: sid = dn
            if isinstance(sid, bytes): sid = dn

            cn_lower = cn.lower()
            is_priv = cn_lower in PRIV_GROUP_CNS
            weight = PRIV_GROUP_CNS.get(cn_lower, 0)
            
            g = ADGroup.objects.create(cn=cn, sid=sid, is_privileged=is_priv, weight=weight)
            self._group_dns[dn] = g
            self._sid_map[sid] = g
            
            nodes_info[dn] = {"type": "group", "dn": dn, "name": cn, "weight": weight, "is_privileged": is_priv}

            # Relacionar Grupo-em-Grupo (Arestas)
            members = getattr(entry, 'member', [])
            if members:
                if not isinstance(members, list): members = [members]
                for mdn in members:
                    edges_mem.append({"src": str(mdn).lower(), "dst": dn, "rel": "MEMBER_OF"})

        # ==================================
        # 2. OBTER E CRIAR OS USUÁRIOS
        # ==================================
        print("[Radar AD] Coletando Usuários (com paginação)...")
        conn.search(
            search_base=self.config.base_dn,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            attributes=['sAMAccountName', 'objectSid', 'distinguishedName', 'displayName', 
                        'department', 'title', 'lastLogonTimestamp', 'pwdLastSet', 'userAccountControl', 'memberOf'],
            paged_size=1000
        )

        now = datetime.now(timezone.utc)
        inactive_threshold_minutes = self.inactive_days * 24 * 60

        for entry in conn.entries:
            username = str(entry.sAMAccountName)
            if username.endswith('$'): continue # Pular contas de maquina
            dn = str(entry.distinguishedName).lower()
            
            try: sid = entry.objectSid.value
            except: sid = dn
            if isinstance(sid, bytes): sid = dn

            last_logon_raw = getattr(entry, 'lastLogonTimestamp', None)
            pwd_last_set_raw = getattr(entry, 'pwdLastSet', None)
            uac_raw = getattr(entry, 'userAccountControl', None)

            last_logon_dt = windows_filetime_to_datetime(last_logon_raw) if last_logon_raw else None
            pwd_last_set_dt = windows_filetime_to_datetime(pwd_last_set_raw) if pwd_last_set_raw else None
            is_disabled = is_account_disabled(uac_raw)
            
            inactive_minutes = 0
            is_inactive = False
            if last_logon_dt:
                inactive_minutes = int((now - last_logon_dt).total_seconds() / 60)
                if inactive_minutes > inactive_threshold_minutes:
                    is_inactive = True
            else:
                inactive_minutes = 9999999
                is_inactive = True

            u = ADUser.objects.create(
                username=username, sid=sid,
                display_name=str(entry.displayName) if 'displayName' in entry else '',
                department=str(entry.department) if 'department' in entry else '',
                title=str(entry.title) if 'title' in entry else '',
                last_logon=last_logon_dt, pwd_last_set=pwd_last_set_dt,
                is_inactive=is_inactive, is_disabled=is_disabled, is_privileged=False
            )
            
            nodes_info[dn] = {
                "type": "user", "dn": dn, "name": username, 
                "inactive_minutes": inactive_minutes, "is_inactive": is_inactive,
                "account_disabled": is_disabled, 
                "last_logon": last_logon_dt.strftime("%Y-%m-%d %H:%M:%S") if last_logon_dt else None
            }

            if 'memberOf' in entry:
                for grp_dn in entry.memberOf:
                    gdn_str = str(grp_dn).lower()
                    edges_mem.append({"src": dn, "dst": gdn_str, "rel": "MEMBER_OF"})
                    if gdn_str in self._group_dns:
                        ADMemberOf.objects.create(user=u, group=self._group_dns[gdn_str])

        # ==================================
        # 3. ALGORITMO DE GRAFOS (BFS)
        # ==================================
        print("[Radar AD] Executando Algoritmo BFS em memória para encontrar caminhos críticos...")
        
        # Build adjacency list
        adj = defaultdict(list)
        for e in edges_mem:
            if e["rel"] == "MEMBER_OF":
                adj[e["src"]].append(e["dst"])

        priv_dns = {dn for dn, n in nodes_info.items() if n.get("type") == "group" and n.get("is_privileged")}
        users_dns = [dn for dn, n in nodes_info.items() if n.get("type") == "user"]
        
        findings = []
        priv_users_set = set()
        
        for u_dn in users_dns:
            u_node = nodes_info[u_dn]
            sam = u_node["name"]

            target_dn, path = bfs_shortest_path_to_any_priv(u_dn, adj, priv_dns, max_depth=15)
            if not target_dn or not path:
                continue
                
            priv_users_set.add(sam)

            priv_info = nodes_info[target_dn]
            hops = max(0, len(path) - 1)
            score = score_for_path(priv_info["weight"], hops)
            
            # Format path human-readable
            human = []
            for pdn in path:
                n = nodes_info.get(pdn)
                if n and n["type"] == "user": human.append(f"user:{n['name']}")
                elif n and n["type"] == "group": human.append(f"group:{n['name']}")
                else: human.append(pdn)

            impact_label = compute_impact_for_finding(priv_info["name"])

            f = {
                "user_dn": u_dn,
                "user": sam,
                "priv_group_dn": target_dn,
                "priv_group": priv_info["name"],
                "path_dn": path,
                "path_human": " -> ".join(human),
                "path_steps": path, # full array
                "path_hops": hops,
                "score": score,
                "impact_label": impact_label,
                "last_logon": u_node["last_logon"],
                "inactive_minutes": u_node["inactive_minutes"],
                "account_disabled": u_node["account_disabled"],
                "is_inactive": u_node["is_inactive"]
            }
            findings.append(f)

        findings.sort(key=lambda x: float(x.get("score", 0)), reverse=True)
        
        # ==================================
        # 4. TRACK DIRECT MEMBERS
        # ==================================
        print("[Radar AD] Calculando Membros Diretos...")
        direct_members = {}
        for group_dn in priv_dns:
            group_info = nodes_info[group_dn]
            direct_members[group_dn] = {
                "group_cn": group_info["name"],
                "group_weight": group_info["weight"],
                "members": []
            }
            
        for e in edges_mem:
            if e["rel"] == "MEMBER_OF":
                dst_dn = e["dst"]
                src_dn = e["src"]
                if dst_dn in priv_dns:
                    src_node = nodes_info.get(src_dn)
                    if src_node:
                        member_info = {"dn": src_dn, "type": src_node["type"]}
                        if src_node["type"] == "user": member_info["sAMAccountName"] = src_node["name"]
                        elif src_node["type"] == "group": member_info["cn"] = src_node["name"]
                        direct_members[dst_dn]["members"].append(member_info)

        # ==================================
        # 5. GERAR DUMP DE INATIVOS
        # ==================================
        inactive_report = []
        inactive_priv = 0
        disabled_priv = 0
        
        for u_dn, u_node in filter(lambda item: item[1]["type"] == "user", nodes_info.items()):
            if u_node["is_inactive"]:
                has_priv = u_node["name"] in priv_users_set
                if has_priv: inactive_priv += 1
                if has_priv and u_node["account_disabled"]: disabled_priv += 1
                
                # Fetch finding info if exists
                priv_info = next((f for f in findings if f["user"] == u_node["name"]), None)
                
                entry = {
                    "user": u_node["name"],
                    "user_dn": u_dn,
                    "last_logon": u_node["last_logon"],
                    "inactive_minutes": u_node["inactive_minutes"],
                    "account_disabled": u_node["account_disabled"],
                    "has_priv_path": has_priv,
                }
                if priv_info:
                    entry["priv_group"] = priv_info["priv_group"]
                    entry["score"] = priv_info["score"]
                    entry["impact_label"] = priv_info["impact_label"]
                    entry["path_hops"] = priv_info["path_hops"]
                
                inactive_report.append(entry)
                
        inactive_report.sort(key=lambda x: (not x["has_priv_path"], -(x.get("inactive_minutes") or 0)))

        # Atualizar BD relacional p/ manter padrao do Django
        ADUser.objects.filter(username__in=priv_users_set).update(is_privileged=True)

        # ==================================
        # 6. CRIAR SNAPSHOT DE RISCOS
        # ==================================
        users_created = len(users_dns)
        
        snapshot = ADRiskSnapshot.objects.create(
            total_users=users_created,
            total_groups=len(self._group_dns),
            privileged_users_count=len(priv_users_set),
            inactive_privileged_count=inactive_priv,
            disabled_privileged_count=disabled_priv,
            findings_data=findings,
            direct_members_data=direct_members,
            inactive_users_data=inactive_report
        )

        print(f"[Radar AD] Varredura Finalizada! Risco Crítico: {inactive_priv} Contas Administrativas Inativas.")
        return snapshot

if __name__ == '__main__':
    # Teste isolado
    scanner = RadarScanner()
    scanner.run_scan()
