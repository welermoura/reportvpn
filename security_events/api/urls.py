from rest_framework.routers import DefaultRouter
from security_events.api.views import WebFilterViewSet, IPSViewSet, AntivirusViewSet

router = DefaultRouter()
router.register(r'webfilter', WebFilterViewSet, basename='webfilter')
router.register(r'ips', IPSViewSet, basename='ips')
router.register(r'antivirus', AntivirusViewSet, basename='antivirus')

urlpatterns = router.urls
