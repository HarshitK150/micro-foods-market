import json
import base64
import hashlib
import hmac
import sys
import requests
from flask import Flask, request

app = Flask(__name__)

def calculate_jwt(username):
    header = (base64.urlsafe_b64encode(json.dumps({
        "alg": "HS256",
        "typ": "JWT"
    }).encode('utf-8'))).decode('utf-8')

    payload = {"username": username}
    payload = (base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8'))).decode('utf-8')

    header_and_payload = (header + '.' + payload).encode('utf-8')

    with open('key.txt', 'r') as key_file:
        key = key_file.read()

    key = key.encode('utf-8')

    signature = hmac.new(key, header_and_payload, hashlib.sha256).hexdigest()

    return header_and_payload.decode('utf-8') + '.' + signature

def get_price(product, jwt):
    URL_price = "http://products:5000/get_price"
    r = requests.get(URL_price, params={'product': product}, headers={'Authorization': jwt})
    r = r.json()

    return r['price']

def add_to_log(event, user, name, jwt):
    URL_log = 'http://logs:5000/add_log'
    r = requests.post(URL_log, data={'event': event, 'user': user, 'name': name}, headers={'Authorization': jwt})

    r = r.json()

    return r['status']

@app.route('/clear', methods=(['GET']))
def clear():
    return 'cleared'

@app.route('/order', methods=(['POST']))
def order():
    order_array = json.loads(request.form.get('order'))
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2, 'cost': 'NULL'})

    cost = 0

    for dict_order in order_array:
        product = dict_order['product']
        quantity = dict_order['quantity']

        price = get_price(product, jwt)

        if price == 'NULL':
            return json.dumps({'status': 3, 'cost': 'NULL'})

        cost += (price * quantity)

    cost = f"{cost:.2f}"

    add_to_log('order', username, 'NULL', jwt)
    return json.dumps({'status': 1, 'cost': cost})