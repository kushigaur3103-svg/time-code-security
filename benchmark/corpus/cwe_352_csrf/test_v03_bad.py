from flask import Flask

app = Flask(__name__)

@app.route("/update", methods=["PUT"])
def update():
    return "ok"
