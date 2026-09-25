import os
from flask import Flask

app = Flask(__name__)
debug = os.environ.get("FLASK_DEBUG") == "true"
app.run(debug=debug)
