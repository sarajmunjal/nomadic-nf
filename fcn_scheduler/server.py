from flask import Flask
from flask import jsonify
from flask import json
from flask import request
from flask import redirect
from flask import make_response

from scheduler import schedule_service

app = Flask(__name__)

ex_name = 'nomadic-nf'
scheduler_context = 0

@app.route("/")
def hello():
    return "<h1 style='color:blue'>Hello There!</h1>"


@app.route("/register-packet", methods=['GET'])
def redirect_to_trigger():
    global scheduler_context
    scheduler_context, trigger_url = schedule_service(scheduler_context)
    print("Scheduler Context: {}".format(scheduler_context))
    new_url = trigger_url + '?' + request.query_string
    print(new_url)
    return redirect(new_url, code=302)

if __name__ == "__main__":
    app.run(host='0.0.0.0')

