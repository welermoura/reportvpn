from .models import AccessLog
from django.shortcuts import redirect
from django.urls import reverse

class AccessLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Log only authenticated users requesting admin pages or other sensitive areas
        # Avoiding static files and automated requests if possible
        if request.user.is_authenticated and request.path.startswith('/admin/'):
            # Get IP Address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')

            AccessLog.objects.create(
                user=request.user,
                path=request.path,
                ip_address=ip,
                method=request.method
            )

        return response

class ForcePasswordChangeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                # Check if user has a profile and if force_password_change is True
                if hasattr(request.user, 'profile') and request.user.profile.force_password_change:
                    # Allow access to password change and logout views
                    path = request.path
                    if not path.endswith('password_change/') and not path.endswith('logout/'):
                         # Redirect to admin password change if inside admin
                        if path.startswith('/admin/'):
                             return redirect('admin:password_change')
            except Exception:
                pass # Fail gracefully if profile issues

        response = self.get_response(request)
        return response
