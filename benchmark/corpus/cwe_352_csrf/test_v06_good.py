from flask import Flask
from flask_wtf.csrf import csrf_protect

app = Flask(__name__)

@csrf_protect
@app.route("/update", methods=["PUT"])
def update():
    return "ok"
