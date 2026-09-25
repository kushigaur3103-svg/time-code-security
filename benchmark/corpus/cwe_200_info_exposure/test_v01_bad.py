import traceback
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/error")
def trigger_error():
    try:
        1 / 0
    except Exception:
        return jsonify({"traceback": traceback.format_exc()}), 500
