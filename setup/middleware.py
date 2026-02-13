from django.shortcuts import redirect
from django.conf import settings
from .utils import is_setup_complete


class SetupRequiredMiddleware:
    """
    Middleware to redirect to setup wizard if setup is not complete
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Paths that don't require setup
        self.exempt_paths = [
            '/setup/',
            '/static/',
            '/media/',
        ]
    
    def __call__(self, request):
        # Check if setup is complete
        if not is_setup_complete(settings.BASE_DIR):
            # Allow access to setup pages and static files
            if not any(request.path.startswith(path) for path in self.exempt_paths):
                return redirect('/setup/')
        
        response = self.get_response(request)
        return response
