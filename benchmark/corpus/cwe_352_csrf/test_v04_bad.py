from flask import Flask
from flask_wtf import csrf

app = Flask(__name__)

@csrf.exempt
@app.route("/update", methods=["PUT"])
def update():
    return "ok"
