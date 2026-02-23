import os
import django
import time
import datetime
import urllib3

urllib3.disable_warnings()

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from integrations.fortianalyzer import FortiAnalyzerClient
from django.utils import timezone

client = FortiAnalyzerClient()
client.config.verify_ssl = False

start = timezone.now() - datetime.timedelta(days=2)
end = timezone.now()
log_filter = 'sessionid==743228902 or user=="rafaelasamc"'

tid = client.start_log_task(start_time=start, end_time=end, limit=1000, log_filter=log_filter)
while True:
    status = client.check_task_status(tid)
    if not status or status.get('percentage', 0) >= 100: break
    time.sleep(1)

res = client.get_task_results(tid, limit=1000)
if res and 'result' in res and 'data' in res['result']:
    print("--- FAZ LOGS RECONSTRUCTED ---")
    data = res['result']['data']
    for log in sorted(data, key=lambda x: x.get('itime', '')):
        t_type = log.get('vpntype') or log.get('tunneltype')
        if t_type == 'ssl-vpn' or str(t_type).startswith('ssl'):
            print(f"[{log.get('itime')}] ACTION={log.get('action')} DUR={log.get('duration')} IP={log.get('remip')} SESS={log.get('sessionid')} USER={log.get('user')}")
