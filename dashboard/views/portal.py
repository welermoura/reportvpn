from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from ..models import PortalModule

@login_required
def portal(request):
    """Main portal selection page"""
    modules = PortalModule.objects.filter(is_active=True).order_by('order')
    return render(request, 'dashboard/portal.html', {'modules': modules})
