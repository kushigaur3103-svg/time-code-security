from flask_login import login_required

@app.route("/account", methods=["GET"])
@login_required
def account():
    return "ok"
