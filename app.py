import os
from pathlib import Path

from flask import Flask, jsonify

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent


def load_api_key():
    env_path = ROOT / "config" / "credentials.txt"
    if not env_path.exists():
        return os.environ.get("SERVICE_API_KEY", "")
    for line in env_path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("SERVICE_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/summarize")
def summarize():
    return jsonify(api_key_configured=bool(load_api_key()))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
