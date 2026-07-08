from django.test import TestCase
from unittest.mock import patch, MagicMock
from django.utils import timezone
import datetime

from vpn_logs.models import VPNLog
from integrations.models import FortiAnalyzerConfig
from vpn_logs.tasks import fetch_vpn_logs_task

class VPNLogsParserTests(TestCase):
    def setUp(self):
        # Create a mock config for FortiAnalyzer
        self.config = FortiAnalyzerConfig.objects.create(
            is_enabled=True,
            host="10.10.1.206",
            username="test_user",
            password="test_password",
            trusted_countries="brazil,united states,argentina"
        )
        
    @patch('vpn_logs.tasks.FortiAnalyzerClient')
    @patch('vpn_logs.tasks.ActiveDirectoryClient')
    def test_log_parsing_success_and_save(self, mock_ad_class, mock_fa_class):
        # Set up mock clients
        mock_fa = MagicMock()
        mock_fa_class.return_value = mock_fa
        mock_fa.start_log_task.return_value = "12345"
        
        # Mock FortiAnalyzer log data returned on get_task_results
        mock_fa.get_task_results.side_effect = [
            {
                'result': {
                    'data': [
                        {
                            'sessionid': '99991',
                            'user': 'welerms',
                            'remip': '186.200.10.20',
                            'date': '2026-06-29',
                            'time': '11:00:00',
                            'duration': '3600',
                            'rcvdbyte': '500000',
                            'sentbyte': '250000',
                            'action': 'tunnel-up',
                            'srccountry': 'Brazil',
                            'srccity': 'Sao Paulo',
                        }
                    ]
                }
            },
            None  # No more batches
        ]
        
        # Set up mock AD response
        mock_ad = MagicMock()
        mock_ad_class.return_value = mock_ad
        mock_ad.get_user_info.return_value = {
            'department': 'Tecnologia',
            'email': 'welerms@example.com',
            'title': 'Engenheiro de Seguranca',
            'display_name': 'Welermoura'
        }
        
        # Run task
        # Pass a mock self since it is bound (or it is a celery task)
        # Note: tasks can be called as a standard function if we mock self
        mock_task_self = MagicMock()
        fetch_vpn_logs_task(mock_task_self)
        
        # Assert database entry was created
        logs = VPNLog.objects.filter(session_id='99991')
        self.assertEqual(logs.count(), 1)
        log = logs.first()
        self.assertEqual(log.user, 'welerms')
        self.assertEqual(log.source_ip, '186.200.10.20')
        self.assertEqual(log.duration, 3600)
        self.assertEqual(log.bandwidth_in, 500000)
        self.assertEqual(log.bandwidth_out, 250000)
        self.assertEqual(log.city, 'Sao Paulo')
        self.assertEqual(log.country_name, 'Brazil')
        self.assertEqual(log.country_code, 'BR') # Mapped correctly in COUNTRY_MAP
        self.assertEqual(log.ad_department, 'Tecnologia')
        self.assertEqual(log.ad_email, 'welerms@example.com')
        self.assertEqual(log.ad_title, 'Engenheiro de Seguranca')
        self.assertEqual(log.ad_display_name, 'Welermoura')

    @patch('vpn_logs.tasks.FortiAnalyzerClient')
    @patch('vpn_logs.tasks.ActiveDirectoryClient')
    def test_log_parsing_site_to_site_discard(self, mock_ad_class, mock_fa_class):
        mock_fa = MagicMock()
        mock_fa_class.return_value = mock_fa
        mock_fa.start_log_task.return_value = "12345"
        mock_fa.get_task_results.side_effect = [
            {
                'result': {
                    'data': [
                        {
                            'sessionid': '99992',
                            'user': '192.168.1.50', # IP address user -> noise or site-to-site
                            'remip': '192.168.1.50',
                            'date': '2026-06-29',
                            'time': '11:05:00',
                            'duration': '120',
                            'action': 'tunnel-up',
                        }
                    ]
                }
            },
            None
        ]
        
        mock_task_self = MagicMock()
        fetch_vpn_logs_task(mock_task_self)
        
        # Should NOT save log
        self.assertEqual(VPNLog.objects.filter(session_id='99992').count(), 0)

    @patch('vpn_logs.tasks.FortiAnalyzerClient')
    @patch('vpn_logs.tasks.ActiveDirectoryClient')
    def test_tunnel_stats_offsets(self, mock_ad_class, mock_fa_class):
        # Create an existing active connection
        start_time = timezone.now() - datetime.timedelta(hours=2)
        log_entry = VPNLog.objects.create(
            session_id='99993',
            user='welerms',
            source_ip='186.200.10.20',
            start_time=start_time,
            start_date=start_time.date(),
            duration=300,
            status='active',
            raw_data={'_duration_offset': 100}
        )
        
        mock_fa = MagicMock()
        mock_fa_class.return_value = mock_fa
        mock_fa.start_log_task.return_value = "12345"
        
        # Mock a tunnel-stats log with updated duration (1200)
        mock_fa.get_task_results.side_effect = [
            {
                'result': {
                    'data': [
                        {
                            'sessionid': '99993',
                            'user': 'welerms',
                            'remip': '186.200.10.20',
                            'date': timezone.now().strftime('%Y-%m-%d'),
                            'time': timezone.now().strftime('%H:%M:%S'),
                            'duration': '1200', # Updated duration
                            'action': 'tunnel-stats',
                        }
                    ]
                }
            },
            None
        ]
        
        mock_task_self = MagicMock()
        fetch_vpn_logs_task(mock_task_self)
        
        # Retrieve and assert log entry was updated
        log_entry.refresh_from_db()
        # Duration updated to: 1200 (duration) - 100 (_duration_offset) = 1100
        self.assertEqual(log_entry.duration, 1100)
