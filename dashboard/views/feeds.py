import os
import re
import datetime
import hashlib
from urllib.parse import urlparse

from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.utils import timezone

FEEDS_DIR = os.path.join(settings.BASE_DIR, 'feeds_data')
BACKUP_DIR = os.path.join(FEEDS_DIR, '_backup')
AUDIT_FILE = os.path.join(FEEDS_DIR, '_audit.log')

def ensure_feed_dirs():
    os.makedirs(FEEDS_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

def is_valid_domain(d):
    return bool(re.match(r'^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$', d))

def is_valid_url(u):
    try:
        result = urlparse(u)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

def is_valid_ip(i):
    return bool(re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)$', i))

def normalize_feed(raw_data, type_str):
    if not raw_data: return []
    out = []
    seen = set()
    for line in raw_data.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        val = line.strip()
        if not val: continue
        
        ok = False
        if type_str == 'domain':
            val = val.lower()
            ok = is_valid_domain(val)
        elif type_str == 'url':
            ok = is_valid_url(val)
        elif type_str == 'ip':
            ok = is_valid_ip(val)
            
        if ok and val not in seen:
            seen.add(val)
            out.append(val)
    return out

def get_feeds_version(files):
    ensure_feed_dirs()
    version_str = ""
    for filename in files.values():
        path = os.path.join(FEEDS_DIR, filename)
        if os.path.exists(path):
            version_str += f"{filename}:{os.path.getmtime(path)}|"
    return hashlib.md5(version_str.encode('utf-8')).hexdigest()

def validate_and_normalize_feed(raw_data, type_str):
    if not raw_data: return [], []
    valid = []
    invalid = []
    seen = set()
    for line in raw_data.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        val = line.strip()
        if not val: continue
        
        ok = False
        if type_str == 'domain':
            val = val.lower()
            ok = is_valid_domain(val)
        elif type_str == 'url':
            ok = is_valid_url(val)
        elif type_str == 'ip':
            ok = is_valid_ip(val)
            
        if ok:
            if val not in seen:
                seen.add(val)
                valid.append(val)
        else:
            invalid.append(line.strip())
    return valid, invalid

def backup_if_exists(filename):
    path = os.path.join(FEEDS_DIR, filename)
    if os.path.exists(path):
        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        backup_name = f"{stamp}__{filename}"
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)

def save_feed(filename, data_list):
    ensure_feed_dirs()
    backup_if_exists(filename)
    
    content = "\n".join(data_list)
    if data_list: content += "\n"
    
    with open(os.path.join(FEEDS_DIR, filename), 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)

def load_feed(filename):
    path = os.path.join(FEEDS_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return ""

def get_last_update(filename):
    path = os.path.join(FEEDS_DIR, filename)
    if os.path.exists(path):
        dt = datetime.datetime.fromtimestamp(os.path.getmtime(path))
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    return "—"

def audit_feed_action(user, ip, bld, blu, bli, wld, wlu, wli):
    ensure_feed_dirs()
    stamp = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{stamp} | {user} | ip={ip} | PUBLISH | BL(d={bld},u={blu},ip={bli}) | WL(d={wld},u={wlu},ip={wli})\n"
    with open(AUDIT_FILE, 'a', encoding='utf-8') as f:
        f.write(line)

def serve_feed(request, filename):
    # Security: prevent directory traversal
    if not re.match(r'^[a-zA-Z0-9_-]+\.txt$', filename):
        return HttpResponse("Invalid filename", status=400)
    
    path = os.path.join(FEEDS_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        return HttpResponse(content, content_type="text/plain; charset=utf-8")
    return HttpResponse("", content_type="text/plain; charset=utf-8", status=404)

@login_required
def fortigate_feeds(request):
    files = {
        'bld': 'blacklist-domains.txt',
        'blu': 'blacklist-urls.txt',
        'bli': 'blacklist-ips.txt',
        'wld': 'whitelist-domains.txt',
        'wlu': 'whitelist-urls.txt',
        'wli': 'whitelist-ips.txt',
    }
    
    if request.method == 'POST':
        raw_bld = request.POST.get('txtBLDomains', '')
        raw_blu = request.POST.get('txtBLUrls', '')
        raw_bli = request.POST.get('txtBLIps', '')
        raw_wld = request.POST.get('txtWLDomains', '')
        raw_wlu = request.POST.get('txtWLUrls', '')
        raw_wli = request.POST.get('txtWLIps', '')
        
        raw_submitted_data = {
            'bld': raw_bld,
            'blu': raw_blu,
            'bli': raw_bli,
            'wld': raw_wld,
            'wlu': raw_wlu,
            'wli': raw_wli,
        }
        
        status_msg = ""
        error_msg = ""
        concurrency_error = False
        syntax_error = False
        
        # 1. Concurrency check
        submitted_version = request.POST.get('feeds_version')
        current_version = get_feeds_version(files)
        if submitted_version and submitted_version != current_version:
            concurrency_error = True
            error_msg = "❌ Erro de Concorrência: As listas foram alteradas por outro usuário (ou em outra aba) desde que você abriu esta página. Para não perder suas alterações, copie seus textos, atualize a página e mescle os dados."
            
        # 2. Syntax Check
        if not concurrency_error:
            bld_list, bld_invalid = validate_and_normalize_feed(raw_bld, 'domain')
            blu_list, blu_invalid = validate_and_normalize_feed(raw_blu, 'url')
            bli_list, bli_invalid = validate_and_normalize_feed(raw_bli, 'ip')
            wld_list, wld_invalid = validate_and_normalize_feed(raw_wld, 'domain')
            wlu_list, wlu_invalid = validate_and_normalize_feed(raw_wlu, 'url')
            wli_list, wli_invalid = validate_and_normalize_feed(raw_wli, 'ip')
            
            invalid_summary = []
            if bld_invalid: invalid_summary.append(f"Blacklist Domínios: {', '.join(bld_invalid)}")
            if blu_invalid: invalid_summary.append(f"Blacklist URLs: {', '.join(blu_invalid)}")
            if bli_invalid: invalid_summary.append(f"Blacklist IPs: {', '.join(bli_invalid)}")
            if wld_invalid: invalid_summary.append(f"Whitelist Domínios: {', '.join(wld_invalid)}")
            if wlu_invalid: invalid_summary.append(f"Whitelist URLs: {', '.join(wlu_invalid)}")
            if wli_invalid: invalid_summary.append(f"Whitelist IPs: {', '.join(wli_invalid)}")
            
            if invalid_summary:
                syntax_error = True
                error_msg = "❌ Erro de Sintaxe: Os seguintes itens possuem formato inválido e devem ser corrigidos antes de salvar:\n- " + "\n- ".join(invalid_summary)
                
        # 3. Save if no errors
        if not concurrency_error and not syntax_error:
            save_feed(files['bld'], bld_list)
            save_feed(files['blu'], blu_list)
            save_feed(files['bli'], bli_list)
            save_feed(files['wld'], wld_list)
            save_feed(files['wlu'], wlu_list)
            save_feed(files['wli'], wli_list)
            
            ip = request.META.get('REMOTE_ADDR', 'unknown')
            user_name = request.user.username if request.user.is_authenticated else 'unknown'
            audit_feed_action(user_name, ip, len(bld_list), len(blu_list), len(bli_list), len(wld_list), len(wlu_list), len(wli_list))
            
            status_msg = "✅ Feeds publicados com sucesso."
            
        request.session['feed_status_msg'] = status_msg
        request.session['feed_error_msg'] = error_msg
        request.session['feed_concurrency_error'] = concurrency_error
        request.session['feed_syntax_error'] = syntax_error
        request.session['feed_raw_submitted_data'] = raw_submitted_data
        return redirect('dashboard:fortigate_feeds')

    # GET request
    status_msg = request.session.pop('feed_status_msg', '')
    error_msg = request.session.pop('feed_error_msg', '')
    concurrency_error = request.session.pop('feed_concurrency_error', False)
    syntax_error = request.session.pop('feed_syntax_error', False)
    raw_submitted_data = request.session.pop('feed_raw_submitted_data', {})
    
    if concurrency_error or syntax_error:
        data = raw_submitted_data
    else:
        data = {k: load_feed(v) for k, v in files.items()}
        
    feeds_version = get_feeds_version(files)
    
    host = request.get_host()
    scheme = request.scheme
    base_url = f"{scheme}://{host}/feeds/"
    
    context = {
        'data': data,
        'status_msg': status_msg,
        'error_msg': error_msg,
        'last_update': get_last_update(files['bld']),
        'base_url': base_url,
        'feeds_version': feeds_version
    }
    
    return render(request, 'dashboard/fortigate_feeds.html', context)
