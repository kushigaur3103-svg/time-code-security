from flask import Flask
from flask_wtf.csrf import csrf_exempt

app = Flask(__name__)

@app.route("/transfer", methods=["POST"])
@csrf_exempt
def transfer():
    return "ok"
