import logging
from flask import Flask, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.route("/error")
def trigger_error():
    try:
        1 / 0
    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": "An internal error occurred"}), 500
