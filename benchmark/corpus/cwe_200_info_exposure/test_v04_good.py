from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/info")
def show_info():
    return jsonify({"status": "healthy"})
