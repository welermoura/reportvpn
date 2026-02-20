from dashboard.models import PortalModule

def portal_modules(request):
    """
    Context processor para injetar a lista de módulos ativos do portal em todos os templates.
    Isso permite que a barra de navegação principal seja gerada dinamicamente.
    """
    try:
        modules = PortalModule.objects.filter(is_active=True).order_by('order')
        return {'portal_modules': modules}
    except Exception:
        # Prevents crash if database is not migrated yet
        return {'portal_modules': []}
