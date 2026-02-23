from rest_framework.routers import DefaultRouter
from security_events.api.views import WebFilterViewSet, IPSViewSet, AntivirusViewSet, AppControlViewSet, ADAuthEventViewSet, RadarADViewSet

router = DefaultRouter()
router.register(r'webfilter', WebFilterViewSet, basename='webfilter')
router.register(r'ips', IPSViewSet, basename='ips')
router.register(r'antivirus', AntivirusViewSet, basename='antivirus')
router.register(r'app-control', AppControlViewSet, basename='app-control')
router.register(r'ad-auth', ADAuthEventViewSet, basename='ad-auth')
router.register(r'radar-ad', RadarADViewSet, basename='radar-ad')

urlpatterns = router.urls
