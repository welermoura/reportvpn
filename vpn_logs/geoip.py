"""GeoIP lookup via ip-api.com with Redis cache and batch support."""
import json
import logging
import requests

logger = logging.getLogger(__name__)

_PRIVATE_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                     '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                     '172.30.', '172.31.', '192.168.', '127.', '0.0.0.0',
                     '169.254.')
_CACHE_TTL = 86400  # 24 h
_FIELDS = 'status,country,countryCode,city,lat,lon'


def _is_private(ip):
    return not ip or any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _redis():
    try:
        import redis as redis_lib
        return redis_lib.Redis(host='redis', port=6379, db=2, decode_responses=True)
    except Exception:
        return None


def get_geoip(ip, redis_client=None):
    """Return {lat, lon, city, country_name, country_code} or {} for private/unknown IPs."""
    if _is_private(ip):
        return {}

    rc = redis_client or _redis()
    cache_key = f'geoip:{ip}'

    if rc:
        try:
            cached = rc.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass

    try:
        r = requests.get(f'http://ip-api.com/json/{ip}',
                         params={'fields': _FIELDS}, timeout=4)
        data = r.json()
        if data.get('status') == 'success':
            result = {
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'city': data.get('city', ''),
                'country_name': data.get('country', ''),
                'country_code': data.get('countryCode', ''),
            }
            if rc:
                try:
                    rc.setex(cache_key, _CACHE_TTL, json.dumps(result))
                except Exception:
                    pass
            return result
    except Exception as e:
        logger.debug(f'GeoIP lookup failed for {ip}: {e}')

    return {}


def batch_geoip(ips, redis_client=None):
    """Batch-lookup up to 100 unique public IPs. Returns {ip: geo_dict}."""
    if not ips:
        return {}

    rc = redis_client or _redis()
    result = {}
    to_fetch = []

    for ip in set(ips):
        if _is_private(ip):
            result[ip] = {}
            continue
        cache_key = f'geoip:{ip}'
        if rc:
            try:
                cached = rc.get(cache_key)
                if cached:
                    result[ip] = json.loads(cached)
                    continue
            except Exception:
                pass
        to_fetch.append(ip)

    # ip-api.com batch: max 100 per call
    for chunk_start in range(0, len(to_fetch), 100):
        chunk = to_fetch[chunk_start:chunk_start + 100]
        try:
            r = requests.post(
                'http://ip-api.com/batch',
                json=[{'query': ip, 'fields': _FIELDS} for ip in chunk],
                timeout=10,
            )
            for item in r.json():
                ip = item.get('query', '')
                if item.get('status') == 'success':
                    geo = {
                        'lat': item.get('lat'),
                        'lon': item.get('lon'),
                        'city': item.get('city', ''),
                        'country_name': item.get('country', ''),
                        'country_code': item.get('countryCode', ''),
                    }
                else:
                    geo = {}
                result[ip] = geo
                if rc and geo:
                    try:
                        rc.setex(f'geoip:{ip}', _CACHE_TTL, json.dumps(geo))
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f'GeoIP batch lookup failed: {e}')
            for ip in chunk:
                result[ip] = {}

    return result
