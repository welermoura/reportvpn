from django.shortcuts import redirect
from django.urls import reverse

class ForcePasswordChangeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and hasattr(request.user, 'profile'):
            if request.user.profile.force_password_change:
                # Define allowed paths (Password change page, logout, and static assets)
                # We assume using the default admin password change view
                try:
                    path_change = reverse('admin:password_change')
                    path_logout = reverse('admin:logout')
                    path_done = reverse('admin:password_change_done')
                except:
                    # Fallback if admin urls are different
                    path_change = '/admin/password_change/'
                    path_logout = '/admin/logout/'
                    path_done = '/admin/password_change/done/'

                allowed = [path_change, path_logout, path_done]
                
                if request.path not in allowed and not request.path.startswith('/static/'):
                    return redirect(path_change)

        response = self.get_response(request)
        return response
