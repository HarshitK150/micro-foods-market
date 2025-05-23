import sqlite3
import os
import json
import base64
import hashlib
import hmac
import sys

import requests
from flask import Flask, request

app = Flask(__name__)
db_name = 'products.db'
sql_file = "products.sql"
db_flag = False

def create_db():
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON")

    with open(sql_file, 'r') as sql_startup:
        init_db = sql_startup.read()
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    return conn


def get_db():
    if not db_flag:
        create_db()

    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

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

def check_employee(jwt):
    URL_user = "http://user:5000/check_employee"
    r = (requests.post(URL_user, headers={'Authorization': jwt}))
    r = r.json()

    if r['status'] == 1:
        return True

    return False


def add_to_log(event, user, name, jwt):
    URL_log = 'http://logs:5000/add_log'
    r = requests.post(URL_log, data={'event': event, 'user': user, 'name': name}, headers={'Authorization': jwt})

    r = r.json()

    return r['status']

@app.route('/clear', methods=(['GET']))
def clear():
    try:
        os.remove(db_name)
        global db_flag
        db_flag = False

    except Exception as e:
        pass
    return 'cleared'

@app.route('/create_product', methods=(['POST']))
def create_product():
    name = request.form.get('name')
    price = request.form.get('price')
    category = request.form.get('category')
    jwt = request.headers['Authorization']

    output = 'empty'

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username) or not check_employee(jwt):
        return json.dumps({'status': 2})

    conn = get_db()
    try:
        cursor = conn.cursor()

        create_query = "INSERT INTO Products (name, price, category) VALUES (?, ?, ?);"
        cursor.execute(create_query, (name, price, category))

        conn.commit()
        conn.close()

        output = json.dumps({'status': 1})
        add_to_log('product_creation', username, name, jwt)

    except Exception as e:
        conn.close()
        output = json.dumps({'status': 2})

    return output

@app.route('/edit_product', methods=(['POST']))
def edit_product():
    name = request.form.get('name')
    new_price = request.form.get('new_price')
    new_category = request.form.get('new_category')
    jwt = request.headers['Authorization']

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2})

    if not check_employee(jwt):
        return json.dumps({'status': 3})

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = "UPDATE Products SET price = ? WHERE name = ?;" if new_price \
                    else "UPDATE Products SET category = ? WHERE name = ?;"

        parameter = (new_price, name) if new_price else (new_category, name)
        cursor.execute(query, parameter)

        conn.commit()
        conn.close()

        output = json.dumps({'status': 1})
        add_to_log('product_edit', username, name, jwt)

    except Exception as e:
        conn.close()
        output = json.dumps({'status': 2})

    return output

@app.route('/get_price', methods=(['GET']))
def get_price():
    product = request.args.get('product')
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2, 'price': 'NULL'})

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = "SELECT price FROM Products WHERE name = ?;"
        cursor.execute(query, (product,))

        price = cursor.fetchone()
        price = 'NULL' if not price else price[0]

        output = json.dumps({'status': 1, 'price': price})

        conn.commit()
        conn.close()

    except Exception as e:
        conn.close()
        output = json.dumps({'status': 2, 'price': 'NULL'})

    return output

@app.route('/search_product', methods=(['GET']))
def search_product():
    product_name = request.args.get('product_name')
    category = request.args.get('category')
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2, 'data': 'NULL'})

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = "SELECT name, price, category FROM Products WHERE name = ?;" if product_name \
                    else "SELECT name, price, category FROM Products WHERE category = ?;"

        param = product_name if product_name else category
        cursor.execute(query, (param,))

        results = cursor.fetchall()
        data = []

        for result in results:
            data.append({'product_name': result[0], 'price': result[1], 'category': result[2]})

        conn.commit()
        conn.close()

        return json.dumps({'status': 1, 'data': data}) if data else json.dumps({'status': 2, 'data': 'NULL'})

    except Exception as e:
        conn.close()

    return json.dumps({'status': 2, 'data': 'NULL'})