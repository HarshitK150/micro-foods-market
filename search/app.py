import json
import base64
import hashlib
import hmac
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

    return header_and_payload.decode('utf-8') + '.' + signature\

def search_products(product_name, category, jwt):
    URL_products = "http://products:5000/search_product"

    param = {'product_name': product_name} if product_name else {'category': category}

    r = requests.get(URL_products, params=param, headers={'Authorization': jwt})
    r = r.json()

    return r['data']

def get_last_mod(product_name, jwt):
    URL_log_mod = "http://logs:5000/last_mod"

    r = requests.get(URL_log_mod, params={'product_name': product_name}, headers={'Authorization': jwt})
    r = r.json()

    return r['last_mod']

def add_to_log(event, user, name, jwt):
    URL_log = 'http://logs:5000/add_log'
    r = requests.post(URL_log, data={'event': event, 'user': user, 'name': name}, headers={'Authorization': jwt})

    r = r.json()

    return r['status']

@app.route('/clear', methods=(['GET']))
def clear():
    return 'cleared'


@app.route('/search', methods=(['GET']))
def search():
    product_name = request.args.get('product_name')
    category = request.args.get('category')
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2, 'data': 'NULL'})

    product_details = search_products(product_name, category, jwt)

    if product_details == 'NULL':
        return json.dumps({'status': 3, 'data': 'NULL'})

    for product in product_details:
        product['last_mod'] = get_last_mod(product['product_name'], jwt)

    name = product_name if product_name else category
    add_to_log('search', username, name, jwt)

    return json.dumps({'status': 1, 'data': product_details})