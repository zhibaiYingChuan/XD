"""道体·玄盾 HTTP API 服务。

用于在 TEE（如 Intel SGX）环境中部署，提供 RESTful 接口。
依赖：Flask（pip install flask）
"""

from flask import Flask, jsonify, request

from daoti_xuandun import XuanDun, XuanDunConfig

app = Flask(__name__)

config = XuanDunConfig()
shield = XuanDun(config)


@app.route("/health", methods=["GET"])
def health():
    """健康检查。"""
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/protect", methods=["POST"])
def protect():
    """防护接口。

    Body JSON:
        {
            "text": "用户输入文本",
            "session": "会话ID（可选，默认 default）"
        }

    Returns:
        {
            "allowed": true/false,
            "reject_stage": "reject_gate" / "timing_checker" / null,
            "timing_distance": 0.0
        }
    """
    data = request.get_json(force=True)
    text = data.get("text", "")
    session = data.get("session", "default")
    result = shield.protect(text, session)
    return jsonify(
        {
            "allowed": result.allowed,
            "reject_stage": result.reject_stage,
            "timing_distance": result.timing_distance,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)