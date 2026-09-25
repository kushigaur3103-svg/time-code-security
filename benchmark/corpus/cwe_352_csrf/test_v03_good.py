from flask import Flask, request
from flask_wtf import FlaskForm

app = Flask(__name__)

class TransferForm(FlaskForm):
    amount = None

@app.route("/transfer", methods=["POST"])
def transfer():
    form = TransferForm(request.form)
    if form.validate_on_submit():
        return "ok"
    return "invalid"
