from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Max
from django.utils import timezone
from datetime import timedelta

from vpn_logs.models import VPNLog, VPNFailure
from security_events.models import ADUser
from integrations.ad import ActiveDirectoryClient


@login_required
def anomaly_dashboard(request):
    return render(request, 'dashboard/anomaly_react.html')


@login_required
def anomaly_stats_api(request):
    days = int(request.GET.get('days', 7))
    since = timezone.now() - timedelta(days=days)

    # Usuários com impossible travel no período
    travel_users = (
        VPNLog.objects
        .filter(impossible_travel=True, start_time__gte=since)
        .values('user', 'ad_display_name', 'ad_department')
        .annotate(travel_count=Count('id'), last_travel=Max('start_time'))
    )
    travel_map = {
        row['user']: {
            'travel_count': row['travel_count'],
            'last_travel': row['last_travel'].isoformat(),
            'display_name': row['ad_display_name'] or row['user'],
            'department': row['ad_department'] or '',
        }
        for row in travel_users
    }

    # Usuários com falhas de autenticação VPN no período
    bf_users = (
        VPNFailure.objects
        .filter(timestamp__gte=since)
        .values('user', 'ad_display_name', 'ad_department')
        .annotate(failure_count=Count('id'), last_failure=Max('timestamp'))
    )
    bf_map = {
        row['user']: {
            'failure_count': row['failure_count'],
            'last_failure': row['last_failure'].isoformat(),
            'display_name': row['ad_display_name'] or '',
            'department': row['ad_department'] or '',
        }
        for row in bf_users
    }

    # Apenas usuários com anomalia VPN real (viagem impossível OU falhas de autenticação)
    all_users = set(travel_map) | set(bf_map)

    # ADUser como fonte canônica (indexado em minúsculo para lookup case-insensitive)
    ad_map = {
        u.username.lower(): {
            'display_name': u.display_name or '',
            'department': u.department or '',
        }
        for u in ADUser.objects.filter(username__in=all_users).only('username', 'display_name', 'department')
    }

    # Complementa com dados de VPNLog quando ADUser não tem o usuário
    for row in (
        VPNLog.objects
        .filter(user__in=all_users)
        .exclude(ad_department='')
        .exclude(ad_department=None)
        .values('user', 'ad_display_name', 'ad_department')
        .order_by('user', '-start_time')
    ):
        key = row['user'].lower()
        if key not in ad_map:
            ad_map[key] = {
                'display_name': row['ad_display_name'] or '',
                'department': row['ad_department'] or '',
            }

    # Para usuários ainda sem departamento, consulta o AD em lote (uma única query LDAP)
    missing = [u for u in all_users if u.lower() not in ad_map]
    if missing:
        try:
            client = ActiveDirectoryClient()
            conn = client.get_connection()
            if conn:
                # Filtro OR com todos os usernames de uma vez
                parts = ''.join(f'(sAMAccountName={u})' for u in missing)
                ldap_filter = f'(|{parts})' if len(missing) > 1 else f'(sAMAccountName={missing[0]})'
                conn.search(
                    search_base=client.config.base_dn,
                    search_filter=f'(&(objectClass=user){ldap_filter})',
                    attributes=['sAMAccountName', 'displayName', 'department'],
                )
                for entry in conn.entries:
                    uname = str(entry.sAMAccountName).lower() if entry.sAMAccountName else None
                    if uname:
                        ad_map[uname] = {
                            'display_name': str(entry.displayName) if entry.displayName else '',
                            'department': str(entry.department) if entry.department else '',
                        }
        except Exception:
            pass

    def get_ad(username):
        return ad_map.get(username.lower(), {})

    rows = []
    for username in all_users:
        travel = travel_map.get(username, {})
        bf = bf_map.get(username, {})
        ad = get_ad(username)

        # Sinais: viagem impossível + brute force (≥5 falhas)
        signals = sum([
            bool(travel.get('travel_count', 0)),
            bf.get('failure_count', 0) >= 5,
        ])

        rows.append({
            'username': username,
            'display_name': ad.get('display_name') or travel.get('display_name') or bf.get('display_name') or username,
            'department': ad.get('department') or travel.get('department') or bf.get('department', ''),
            'impossible_travel': travel.get('travel_count', 0),
            'last_travel': travel.get('last_travel'),
            'brute_force_failures': bf.get('failure_count', 0),
            'last_failure': bf.get('last_failure'),
            'active_signals': signals,
        })

    # Ordena por sinais ativos desc, depois por brute force desc
    rows.sort(key=lambda r: (-r['active_signals'], -r['brute_force_failures']))

    summary = {
        'total_anomalous_users': len(rows),
        'impossible_travel_users': len(travel_map),
        'brute_force_users': sum(1 for r in rows if r['brute_force_failures'] >= 5),
        'multi_signal_users': sum(1 for r in rows if r['active_signals'] >= 2),
    }

    return JsonResponse({'summary': summary, 'users': rows[:50], 'days': days})
