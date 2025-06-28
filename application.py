from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, redirect, request, send_file
from random import random
from time import sleep
from threading import Thread, Event
from datetime import datetime

from scapy.sendrecv import sniff

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import numpy as np
import pickle
import csv
import traceback

import json
import pandas as pd
import csv

from scipy.stats import norm

import ipaddress
from urllib.request import urlopen

from tensorflow import keras

from lime import lime_tabular

import dill

import joblib

import plotly
import plotly.graph_objs

import warnings
warnings.filterwarnings("ignore")

import requests
import re


def ipInfo(addr=''):
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url)
        data = json.load(res)
        return data['country']
    except Exception:
        return None


__author__ = 'hoang'


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

thread = Thread()
thread_stop_event = Event()

f = open("output_logs.csv", 'w')
w = csv.writer(f)
f2 = open("input_logs.csv", 'w')
w2 = csv.writer(f2)

cols = ['FlowID',
'FlowDuration',
'BwdPacketLenMax',
'BwdPacketLenMin',
'BwdPacketLenMean',
'BwdPacketLenStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets_s',
'MaxPacketLen',
'PacketLenMean',
'PacketLenStd',
'PacketLenVar',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AvgPacketSize',
'AvgBwdSegmentSize',
'InitWinBytesFwd',
'InitWinBytesBwd',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin',
'Src',
'SrcPort',
'Dest',
'DestPort',
'Protocol',
'FlowStartTime',
'FlowLastSeen',
'PName',
'PID',
'Classification',
'Probability',
'Risk']

ae_features = np.array(['FlowDuration',
'BwdPacketLengthMax',
'BwdPacketLengthMin',
'BwdPacketLengthMean',
'BwdPacketLengthStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets/s',
'PacketLengthMax',
'PacketLengthMean',
'PacketLengthStd',
'PacketLengthVariance',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AveragePacketSize',
'BwdSegmentSizeAvg',
'FWDInitWinBytes',
'BwdInitWinBytes',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin'])

flow_count = 0
flow_df = pd.DataFrame(columns=cols)

src_ip_dict = {}

current_flows = {}
FlowTimeout = 2

# Load models
ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
ae_model = keras.models.load_model('models/autoencoder_39ft.hdf5')

with open('models/model.pkl', 'rb') as f:
    classifier = pickle.load(f)

with open('models/explainer', 'rb') as f:
    explainer = dill.load(f)

predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)

TELEGRAM_TOKEN = 
TELEGRAM_CHAT_ID = 

def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'HTML'
    }
    try:
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            print(f"Telegram message failed: {response.text}")
    except Exception as e:
        print(f"Exception while sending telegram message: {e}")

def classify(features):
    global flow_count
    feature_string = [str(i) for i in features[39:]]
    record = features.copy()
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]

    if feature_string[0] in src_ip_dict.keys():
        src_ip_dict[feature_string[0]] += 1
    else:
        src_ip_dict[feature_string[0]] = 1

    for i in [0, 2]:
        ip = feature_string[i]
        if not ipaddress.ip_address(ip).is_private:
            country = ipInfo(ip)
            if country is not None and country not in ['ano', 'unknown']:
                img = ' <img src="static/images/blank.gif" class="flag flag-' + country.lower() + '" title="' + country + '">'
            else:
                img = ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
        else:
            img = ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
        feature_string[i] += img

    if np.nan in features:
        return

    result = classifier.predict([features])
    proba = predict_fn_rf([features])
    proba_score = [proba[0].max()]
    proba_risk = sum(list(proba[0, 1:]))

    if proba_risk > 0.8:
        risk = ["<p style=\"color:red;\">Very High</p>"]
    elif proba_risk > 0.6:
        risk = ["<p style=\"color:orangered;\">High</p>"]
    elif proba_risk > 0.4:
        risk = ["<p style=\"color:orange;\">Medium</p>"]
    elif proba_risk > 0.2:
        risk = ["<p style=\"color:green;\">Low</p>"]
    else:
        risk = ["<p style=\"color:limegreen;\">Minimal</p>"]

    blocked_ips = set()
    classification = [str(result[0])]
    current_ip_address = feature_string[0].split(" ")[0]

    if result != 'Benign':
        blocked_ips.add(current_ip_address)
        log_blocked_ip(current_ip_address, result)

        risk_level = risk[0]
        risk_text = re.sub('<[^<]+?>', '', risk_level)

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        protocol_used = feature_string[4] if len(feature_string) > 4 else "Unknown"
        action = "⛔ Blocked" if current_ip_address in blocked_ips else "⚠️ Alert Only"

        message = (
            f"🚨 <b>[APT Detection Alert]</b>\n"
            f"🕒 <b>Time:</b> {now}\n"
            f"🌐 <b>IP:</b> {current_ip_address}\n"
            f"💥 <b>Threat:</b> {classification[0]}\n"
            f"📡 <b>Protocol:</b> {protocol_used}\n"
            f"🔒 <b>Action:</b> {action}\n"
            f"⚠️ <b>Risk Level:</b> {risk_text}"
        )

        send_telegram_message(message)

        print(feature_string + classification + proba_score)

    flow_count += 1
    w.writerow(['Flow #' + str(flow_count)])
    w.writerow(['Flow info:'] + feature_string)
    w.writerow(['Flow features:'] + features)
    w.writerow(['Prediction:'] + classification + proba_score)
    w.writerow(['--------------------------------------------------------------------------------------------------'])

    w2.writerow(['Flow #' + str(flow_count)])
    w2.writerow(['Flow info:'] + features)
    w2.writerow(['--------------------------------------------------------------------------------------------------'])

    flow_df.loc[len(flow_df)] = [flow_count] + record + classification + proba_score + risk

    ip_data = {'SourceIP': src_ip_dict.keys(), 'count': src_ip_dict.values()}
    ip_data = pd.DataFrame(ip_data)
    ip_data = ip_data.to_json(orient='records')

    socketio.emit('newresult', {'result': [flow_count] + feature_string + classification + proba_score + risk, "ips": json.loads(ip_data)}, namespace='/test')

    return [flow_count] + record + classification + proba_score + risk


def log_blocked_ip(ip_address, prediction):
    with open('blocked_ips_list.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        if f.tell() == 0:
            writer.writerow(['timestamp', 'ip_address', 'prediction'])
        writer.writerow([datetime.now().isoformat(), ip_address, prediction])


def block_ip_with_windows_firewall(ip):
    import subprocess
    try:
        rule_name = f"Block {ip}"
        subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            'dir=in',
            'action=block',
            f'remoteip={ip}'
        ])
        return True
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")
        return False


def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow

    except AttributeError:
        return

    except:
        traceback.print_exc()


def snif_and_detect():
    while not thread_stop_event.isSet():
        print(" Begin Sniffing on Wi-Fi interface".center(10, '-'))
        sniff(iface="Wi-Fi", prn=newPacket, store=0)
        for f in list(current_flows.values()):
            classify(f.terminated())


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_user():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'admin' and password == 'password123':
        return redirect(url_for('index'))
    else:
        return "Invalid credentials", 401


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/logout')
def logout():
    return redirect(url_for('login'))


@app.route('/download/output-logs')
def download_output_logs():
    return send_file("output_logs.csv", as_attachment=True)


@app.route('/download/input-logs')
def download_input_logs():
    return send_file("input_logs.csv", as_attachment=True)

@app.route('/ipscan')
def ipscan():
    clients = []
    try:
        with open('ipscan.csv', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                clients.append(row)
    except Exception as e:
        print(f"Erreur lecture ipscan.csv: {e}")

    return render_template('ipscan.html', clients=clients)

@app.route('/rapport')
def rapport():
    return render_template('rapport.html')


@app.route('/tableau')
def tableau():
    return render_template('tableau.html')


@app.route('/graphe')
def graphe():
    return render_template('graphe.html')


blocked_ips = set()


@app.route('/ip_control')
def ip_control():
    ip_list = []
    for ip, count in src_ip_dict.items():
        ip_list.append({
            'ip': ip,
            'count': count,
            'blocked': ip in blocked_ips
        })
    return render_template('ip_control.html', ips=ip_list)


@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.form.get('ip')
    if ip:
        blocked_ips.add(ip)
        return 'Blocked', 200
    return 'Invalid', 400


@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    ip = request.form.get('ip')
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        return 'Unblocked', 200
    return 'Not Found', 400


@app.route('/flow-detail')
def flow_detail():
    flow_id = request.args.get('flow_id', default=-1, type=int)
    flow = flow_df.loc[flow_df['FlowID'] == flow_id]
    X = [flow.values[0, 1:40]]
    choosen_instance = X
    proba_score = list(predict_fn_rf(choosen_instance))
    risk_proba = sum(proba_score[0][1:])
    if risk_proba > 0.8:
        risk = "Risk: <p style=\"color:red;\">Very High</p>"
    elif risk_proba > 0.6:
        risk = "Risk: <p style=\"color:orangered;\">High</p>"
    elif risk_proba > 0.4:
        risk = "Risk: <p style=\"color:orange;\">Medium</p>"
    elif risk_proba > 0.2:
        risk = "Risk: <p style=\"color:green;\">Low</p>"
    else:
        risk = "Risk: <p style=\"color:limegreen;\">Minimal</p>"
    exp = explainer.explain_instance(choosen_instance[0], predict_fn_rf, num_features=6, top_labels=1)

    X_transformed = ae_scaler.transform(X)
    reconstruct = ae_model.predict(X_transformed)
    err = reconstruct - X_transformed
    abs_err = np.absolute(err)

    ind_n_abs_largest = np.argpartition(abs_err, -5)[-5:]

    col_n_largest = ae_features[ind_n_abs_largest]
    err_n_largest = err[0][ind_n_abs_largest]
    plot_div = plotly.offline.plot({
        "data": [
            plotly.graph_objs.Bar(x=col_n_largest[0].tolist(), y=err_n_largest[0].tolist())
        ]
    }, include_plotlyjs=False, output_type='div')

    return render_template('detail.html', tables=[flow.reset_index(drop=True).transpose().to_html(classes='data')], exp=exp.as_html(), ae_plot=plot_div, risk=risk)


@socketio.on('connect', namespace='/test')
def test_connect():
    global thread
    print('Client connected')

    if not thread.is_alive():
        print("Starting Thread")
        thread = socketio.start_background_task(snif_and_detect)


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
