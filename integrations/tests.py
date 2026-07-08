from django.test import TestCase
from unittest.mock import patch, MagicMock
import json

from integrations.models import ActiveDirectoryConfig
from integrations.ad import ActiveDirectoryClient

class ActiveDirectoryClientTests(TestCase):
    def setUp(self):
        # Create a mock AD config
        self.config = ActiveDirectoryConfig.objects.create(
            server="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_user="cn=admin,dc=example,dc=com",
            bind_password="adminpassword",
            base_dn="dc=example,dc=com"
        )

    def test_client_connection_with_no_server(self):
        # Set server to empty
        self.config.server = ""
        self.config.save()
        
        client = ActiveDirectoryClient()
        self.assertIsNone(client.get_connection())

    @patch('integrations.ad.Connection')
    @patch('integrations.ad.Server')
    def test_get_user_info_success(self, mock_server, mock_connection):
        # Setup mock connection and search entries
        mock_conn_instance = MagicMock()
        mock_connection.return_value = mock_conn_instance
        
        mock_entry = MagicMock()
        mock_entry.mail = 'welerms@example.com'
        mock_entry.department = 'Tecnologia'
        mock_entry.displayName = 'Welermoura'
        mock_entry.title = 'Engenheiro'
        
        mock_conn_instance.entries = [mock_entry]
        
        client = ActiveDirectoryClient()
        info = client.get_user_info("welerms")
        
        # Verify connection search was called with correct DN and filters
        mock_conn_instance.search.assert_called_once_with(
            search_base="dc=example,dc=com",
            search_filter="(&(objectClass=user)(sAMAccountName=welerms))",
            attributes=['mail', 'department', 'displayName', 'title']
        )
        
        # Assert returned dict matches
        self.assertIsNotNone(info)
        self.assertEqual(info['email'], 'welerms@example.com')
        self.assertEqual(info['department'], 'Tecnologia')
        self.assertEqual(info['display_name'], 'Welermoura')
        self.assertEqual(info['title'], 'Engenheiro')

    @patch('integrations.ad.redis_client')
    @patch('integrations.ad.Connection')
    @patch('integrations.ad.Server')
    def test_get_user_info_caches_results(self, mock_server, mock_connection, mock_redis):
        # Ensure redis is enabled for the mock
        mock_redis.get.return_value = None
        
        # Setup connection
        mock_conn_instance = MagicMock()
        mock_connection.return_value = mock_conn_instance
        
        mock_entry = MagicMock()
        mock_entry.mail = 'cached@example.com'
        mock_entry.department = 'Marketing'
        mock_entry.displayName = 'Cached User'
        mock_entry.title = 'Analyst'
        mock_conn_instance.entries = [mock_entry]
        
        client = ActiveDirectoryClient()
        
        # First call -> Queries AD and saves to Redis
        info1 = client.get_user_info("cached_user")
        self.assertEqual(info1['email'], 'cached@example.com')
        mock_redis.setex.assert_called_once()
        
        # Mock subsequent call fetching from Redis cache directly
        mock_redis.get.return_value = json.dumps({
            'email': 'cached@example.com',
            'department': 'Marketing',
            'display_name': 'Cached User',
            'title': 'Analyst'
        })
        
        # Second call -> Directly from cache, no second AD Connection search
        mock_conn_instance.search.reset_mock()
        info2 = client.get_user_info("cached_user")
        
        self.assertEqual(info2['email'], 'cached@example.com')
        mock_conn_instance.search.assert_not_called()
