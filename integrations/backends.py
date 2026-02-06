import ldap3
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User, Group
from .models import ActiveDirectoryConfig
# Configure File Logging for Debugging
import logging
debug_logger = logging.getLogger('ad_debug')
handler = logging.FileHandler('ad_auth.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
debug_logger.addHandler(handler)
debug_logger.setLevel(logging.DEBUG)

class ADLdap3Backend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        debug_logger.info(f"Attempting auth for user: {username}")
        
        if not username or not password:
            return None
            
        config = ActiveDirectoryConfig.load()
        if not config or not config.server:
            debug_logger.error("AD Config missing or server not set.")
            return None

        try:
            server = ldap3.Server(config.server, port=config.port, use_ssl=config.use_ssl, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=config.bind_user, password=config.bind_password, auto_bind=True)
            debug_logger.info("Bind successful with service account.")
        except Exception as e:
            debug_logger.error(f"AD Bind Failed: {e}")
            return None

        # 2. Search for User
        search_filter = f'(sAMAccountName={username})'
        conn.search(config.base_dn, search_filter, attributes=['distinguishedName', 'memberOf', 'mail', 'givenName', 'sn'])
        
        if not conn.entries:
            debug_logger.warning(f"User {username} not found in AD.")
            return None
            
        user_entry = conn.entries[0]
        user_dn = user_entry.distinguishedName.value
        debug_logger.info(f"User found: {user_dn}")
        
        # 3. Verify User Credentials (Bind as User)
        try:
            user_conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            debug_logger.info(f"User {username} credentials valid.")
        except Exception as e:
            debug_logger.warning(f"User {username} password incorrect: {e}")
            return None
            
        # 4. Group Sync Logic
        # Parse AD Groups
        ad_group_names = []
        if user_entry.memberOf:
             # handle single value vs list
             member_of_vals = user_entry.memberOf.values if hasattr(user_entry.memberOf, 'values') else user_entry.memberOf
             if isinstance(member_of_vals, str): member_of_vals = [member_of_vals]
             
             for group_dn in member_of_vals:
                cn_part = group_dn.split(',')[0]
                if cn_part.upper().startswith('CN='):
                    name = cn_part[3:]
                    ad_group_names.append(name)
                else:
                    ad_group_names.append(cn_part)
        
        debug_logger.info(f"AD Groups found for user: {ad_group_names}")

        # 5. Get or Create Django User
        try:
            user, created = User.objects.get_or_create(username=username)
            
            # Update attributes
            user.email = str(user_entry.mail.value) if user_entry.mail else ''
            user.first_name = str(user_entry.givenName.value) if user_entry.givenName else ''
            user.last_name = str(user_entry.sn.value) if user_entry.sn else ''
            
            # Managed by AD, so unusable local password
            user.set_unusable_password() 
            
            # Sync Groups: Case-Insensitive Match
            # Fetch all Django groups
            all_django_groups = Group.objects.all()
            matching_groups = []
            
            # Create a set of lowercased AD group names for fast lookup
            ad_groups_lower = {g.lower() for g in ad_group_names}
            
            for d_group in all_django_groups:
                if d_group.name.lower() in ad_groups_lower:
                    matching_groups.append(d_group)
            
            debug_logger.info(f"Matching Django Groups: {[g.name for g in matching_groups]}")

            if matching_groups:
                user.groups.set(matching_groups)
                # If matched valid groups, grant staff access to Admin
                user.is_staff = True
                debug_logger.info("Access GRANTED (is_staff=True)")
            else:
                # No matching groups -> No Admin access
                if not user.is_superuser:
                    user.is_staff = False
                debug_logger.warning("No matching groups found. Access DENIED (is_staff=False)")

            user.save()
            return user
            
        except Exception as e:
            debug_logger.error(f"Error creating/updating user {username}: {e}")
            return None
            
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
