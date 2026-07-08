import time, sys
sys.path.insert(0, "src")
from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel
from flask import Flask, jsonify, request

app = Flask(__name__)
config = XuanDunConfig.for_level(DefenseLevel.STANDARD)
shield = XuanDun(config)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/protect", methods=["POST"])
def protect():
    data = request.get_json(force=True)
    text = data.get("text", "")
    session = data.get("session", "default")
    t0 = time.perf_counter()
    result = shield.protect(text, session)
    lat = (time.perf_counter() - t0) * 1000
    return jsonify({
        "allowed": result.allowed,
        "trust_level": result.trust_level.value if hasattr(result.trust_level, "value") else str(result.trust_level),
        "reject_stage": result.reject_stage,
        "lat_ms": round(lat, 1),
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=18766, threaded=True)
