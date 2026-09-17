import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Vulnerable: shell=True with user input (OS command injection)
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return result.stdout

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # Vulnerable: unescaped template rendering (XSS / SSTI risk)
    template = "Hello " + name + "!"
    return render_template_string(template)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
