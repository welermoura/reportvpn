import redis

try:
    r = redis.Redis(host='redis', port=6379, db=2, decode_responses=True)
    dev_id = 'FGT80FTK22016583'
    key = f"device_interfaces_{dev_id}"
    r.delete(key) # Clear old test data
    r.sadd(key, 'wan1|Internet Principal', 'wan2|Internet-Embratel;20', 'port4|Rede DMZ', 'vl_guest')
    r.expire(key, 86400)
    print("New Alias mock data successfully injected into Redis for", dev_id)
except Exception as e:
    print("Error:", e)
