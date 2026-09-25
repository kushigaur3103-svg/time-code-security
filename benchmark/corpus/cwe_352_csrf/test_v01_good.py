from flask import Flask
from flask_wtf.csrf import csrf_protect

app = Flask(__name__)

@app.route("/transfer", methods=["POST"])
@csrf_protect
def transfer():
    return "ok"
