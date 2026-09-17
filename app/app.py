import shlex
import subprocess
from flask import Flask, request, escape

app = Flask(__name__)

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Fixed: strict allow-list validation, no shell=True, no string concatenation
    if host not in ALLOWED_HOSTS:
        return "Host not allowed", 400
    result = subprocess.run(["/bin/ping", "-c", "1", host], capture_output=True)
    return result.stdout

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # Fixed: output is escaped, no template string built from user input (no SSTI)
    return f"Hello {escape(name)}!"

if __name__ == "__main__":
    # Fixed: debug disabled, bound to loopback only
    app.run(host="127.0.0.1", debug=False)
