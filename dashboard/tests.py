from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
import datetime
import json

from vpn_logs.models import VPNLog, VPNFailure
from dashboard.models import PortalModule, UserRiskScore

class DashboardViewsAndAPITests(TestCase):
    def setUp(self):
        self.client = Client()
        
        # Create a test user
        self.username = "testadmin"
        self.password = "securepass123"
        self.user = User.objects.create_user(username=self.username, password=self.password)
        
        # Create active portal module
        self.module = PortalModule.objects.create(
            name="Auditoria de VPN",
            url="/portal/vpn-reports/",
            icon_class="fas fa-network-wired",
            is_active=True,
            order=1
        )
        
        # Create mock VPN Logs for stats testing
        self.log_date = timezone.now().date()
        self.log1 = VPNLog.objects.create(
            session_id="session101",
            user="welerms",
            source_ip="186.200.10.20",
            start_time=timezone.now(),
            start_date=self.log_date,
            duration=3600,
            bandwidth_in=100000,
            bandwidth_out=200000,
            ad_department="Tecnologia",
            ad_title="Engenheiro de Seguranca",
            status="closed",
            raw_data={"tunneltype": "ssl"}
        )
        self.log2 = VPNLog.objects.create(
            session_id="session102",
            user="moura",
            source_ip="186.200.10.21",
            start_time=timezone.now(),
            start_date=self.log_date,
            duration=1800,
            bandwidth_in=50000,
            bandwidth_out=50000,
            ad_department="Seguranca",
            ad_title="Analista",
            status="closed",
            raw_data={"tunneltype": "ssl"}
        )
        
        # Create mock VPN Failure
        self.failure = VPNFailure.objects.create(
            user="admin_target",
            source_ip="45.10.20.30",
            timestamp=timezone.now(),
            country_code="CN"
        )
        
        # Create mock UserRiskScore
        self.risk_score = UserRiskScore.objects.create(
            username="welerms",
            current_score=85,
            risk_level="Alto",
            last_updated=timezone.now()
        )

    def test_portal_view_requires_login(self):
        # Access unauthenticated
        response = self.client.get(reverse('dashboard:index'))
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response.url)

    def test_portal_view_authenticated(self):
        # Login first
        self.client.login(username=self.username, password=self.password)
        
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/portal.html')
        self.assertContains(response, "Auditoria de VPN")

    def test_dashboard_stats_api_authenticated(self):
        self.client.login(username=self.username, password=self.password)
        
        response = self.client.get(reverse('dashboard:stats_api'), {'date': self.log_date.strftime('%Y-%m-%d')})
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        
        # Assert response keys exist
        self.assertIn('connections_trend', data)
        self.assertIn('departments', data)
        self.assertIn('titles', data)
        self.assertIn('users', data)
        self.assertIn('failures', data)
        self.assertIn('period_stats', data)
        
        # Assert aggregations are accurate
        self.assertEqual(data['period_stats']['total_connections'], 2)
        self.assertEqual(data['period_stats']['active_users'], 2)
        
        # Total volume: (100000 + 200000 + 50000 + 50000) = 400000 bytes
        self.assertEqual(data['period_stats']['total_volume_bytes'], 400000)
        
        # Top departments contains mock department
        self.assertIn('Tecnologia', data['departments']['labels'])
        self.assertIn('Seguranca', data['departments']['labels'])

    def test_bruteforce_stats_api_authenticated(self):
        self.client.login(username=self.username, password=self.password)
        
        response = self.client.get(reverse('dashboard:bruteforce_stats_api'))
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertIn('trend', data)
        self.assertIn('ips', data)
        self.assertIn('users', data)
        
        # Assert top target username exists
        self.assertIn('admin_target', data['users']['labels'])
        self.assertIn('45.10.20.30 (CN)', data['ips']['labels'])

    def test_risk_stats_api_authenticated(self):
        self.client.login(username=self.username, password=self.password)
        
        response = self.client.get(reverse('dashboard:risk_stats_api'))
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertIn('distribution', data)
        self.assertIn('top_risk', data)
        
        # Assert High Risk level in distribution labels
        self.assertIn('Alto', data['distribution']['labels'])
        # Assert high risk user exists
        self.assertIn('welerms', data['top_risk']['labels'])

    def test_invalid_url_redirects_to_login_when_unauthenticated(self):
        # Access an invalid URL when not logged in
        response = self.client.get('/uma_pagina_que_nao_existe/')
        # It should redirect directly to the login page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/admin/login/')

    def test_invalid_url_redirects_to_dashboard_when_authenticated(self):
        # Login first
        self.client.login(username=self.username, password=self.password)
        # Access an invalid URL when logged in
        response = self.client.get('/uma_pagina_que_nao_existe/')
        # It should redirect straight to the dashboard portal
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/')

    def test_missing_static_url_returns_404(self):
        # Access a missing static file URL (e.g. /static/css/missing.css)
        response = self.client.get('/static/css/missing.css')
        # It should return a 404 rather than redirecting, to prevent mime-type console issues
        self.assertEqual(response.status_code, 404)
