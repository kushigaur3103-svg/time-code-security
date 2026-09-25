import os
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/version")
def get_version():
    return jsonify({"version": os.environ.get("APP_VERSION", "1.0.0")})
