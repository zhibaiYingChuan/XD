import urllib.request, json, time

lats = []
for i in range(5):
    data = json.dumps({"text":"Hello world","mode":"balanced"}).encode()
    s = time.perf_counter()
    req = urllib.request.Request("http://localhost:18765/protect",data=data,headers={"Content-Type":"application/json"},method="POST")
    resp = urllib.request.urlopen(req, timeout=10)
    d = json.loads(resp.read())
    lat = (time.perf_counter()-s)*1000
    lats.append(lat)
    a = d.get("allowed")
    print("  req %d: %.1fms allowed=%s trust=%s" % (i, lat, a, d.get("trust_level")))
print("avg=%.1fms" % (sum(lats)/len(lats)))
