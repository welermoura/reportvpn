import sys
import os
import django
import datetime
from django.utils import timezone
import time

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from integrations.fortianalyzer import FortiAnalyzerClient

fa_client = FortiAnalyzerClient()

# Search for the last 3 days
start_time = timezone.now() - datetime.timedelta(days=3)
filter_str = 'subtype=="vpn" and user=="rafaelasamc"'

print(f"Starting FA task for: {filter_str}")
tid = fa_client.start_log_task(log_type="event", start_time=start_time, limit=5000, log_filter=filter_str)

print(f"TID: {tid}. Waiting 15 seconds...")
time.sleep(15)

res = fa_client.get_task_results(tid, limit=5000)

logs_data = []
if res and 'result' in res:
    res_data = res['result']
    if isinstance(res_data, dict):
        logs_data = res_data.get('data', [])
    elif isinstance(res_data, list) and len(res_data) > 0:
        logs_data = res_data[0].get('data', [])

print(f"Found {len(logs_data)} logs for rafaelasamc.")
for log in logs_data:
    print(f"Date: {log.get('date')} {log.get('time')} | Action: {log.get('action')} | Duration: {log.get('duration')} | Rcv: {log.get('rcvdbyte')} | Sent: {log.get('sentbyte')} | SessionID: {log.get('sessionid')} | TunnelID: {log.get('tunnelid')}")
