import urllib.request, json, time

# Health
r = urllib.request.urlopen('http://localhost:18765/health')
print("Health:", json.loads(r.read()))

# Single protect
data = json.dumps({"text":"Hello world","mode":"balanced"}).encode()
s = time.perf_counter()
req = urllib.request.Request('http://localhost:18765/protect',data=data,headers={'Content-Type':'application/json'},method='POST')
resp = urllib.request.urlopen(req, timeout=30)
d = json.loads(resp.read())
lat = (time.perf_counter()-s)*1000
print("Protect: lat=%.1fms allowed=%s trust=%s stage=%s" % (lat, d.get('allowed'), d.get('trust_level'), d.get('reject_stage')))

# Benchmark
r = urllib.request.urlopen('http://localhost:18765/benchmark')
d = json.loads(r.read())
print("Benchmark:", d)
