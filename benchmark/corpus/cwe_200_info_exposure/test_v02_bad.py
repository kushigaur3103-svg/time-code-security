import os
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/debug/env")
def dump_env():
    return jsonify(dict(os.environ))
