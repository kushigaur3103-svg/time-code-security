import sys
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/info")
def show_info():
    exc_type, exc_val, exc_tb = sys.exc_info()
    return jsonify({"exc": str(exc_val)})
