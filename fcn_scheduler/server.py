from flask import Flask
from flask import jsonify
from flask import json
from flask import request
from flask import redirect
from flask import make_response

from scheduler import schedule_service

import json
import argparse

import requests

app = Flask(__name__)

ex_name = 'nomadic-nf'
scheduler_context = 0

MODE = None
FLOW_SIZE = 10

flow_map = {}

DNS_URL = "https://us-central1-stable-house-183720.cloudfunctions.net/dnsdetect"

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

def schedule_trigger():
    global scheduler_context
    scheduler_context, trigger_url = schedule_service(scheduler_context)
    return trigger_url

def make_flow_request(flow):
    FLOW_URL = "https://us-central1-stable-house-183720.cloudfunctions.net/flowfunc"
    res = requests.post(FLOW_URL, json=flow)
    print(res.status_code)
    print(res.text)

def aggregate_flow(packet):
    flow_key_1 = packet['sport'] + packet['dport']
    flow_key_2 = packet['dport'] + packet['sport']
    if flow_key_1 in flow_map or flow_key_2 in flow_map:
        flow_key = None
        if flow_key_1 in flow_map:
            flow_key = flow_key_1

        if flow_key_2 in flow_map:
            flow_key = flow_key_2

        flow_map[flow_key].append(packet)

        if len(flow_map[flow_key]) == FLOW_SIZE:
            make_flow_request(flow_map[flow_key])

    else:
        flow_map[flow_key_1] = [packet] 

@app.route("/flowsize", methods=['GET'])
def get_flow_size():
    flow_size = {}
    for flow in flow_map:
        print(len(flow_map[flow]))
        flow_size[flow] = str(len(flow_map[flow]))
    return json.dumps(flow_size, 200, {'ContentType':'application/json'})

@app.route("/test", methods=['POST'])
def test_route():
    print(request.json)
    return json.dumps({'success':True}, 200, {'ContentType':'application/json'})

@app.route("/dns-packet", methods=['POST'])
def receive_dns_packet():
    print("DNS Packet received: {}".format(request.json))
    dns_packet = request.json
    trigger_url = schedule_trigger()
    trigger_url = "https://us-central1-stable-house-183720.cloudfunctions.net/dnsdetect"
    print("Trigger URL: {}".format(trigger_url))
    return redirect(trigger_url, code=302)
    #return json.dumps({'success':True}, 200, {'ContentType':'application/json'})


@app.route("/packet", methods=['POST'])
def receive_packet():
    packet = request.json
    trigger_url = schedule_trigger()
    print("Trigger URL: {}".format(trigger_url))
    return redirect(trigger_url, code=302)
    #return json.dumps({'success':True}, 200, {'ContentType':'application/json'})


@app.route("/flow", methods=['POST'])
def receive_flow():
    packet = request.json
    aggregate_flow(packet)
    return json.dumps({'success':True}, 200, {'ContentType':'application/json'})


if __name__ == "__main__":
    # mode, flow_size= parse_input_args()    
    # print("Mode: {}".format(mode))
    # print("Flow Size: {}".format(flow_size))
    app.run(host='0.0.0.0')

