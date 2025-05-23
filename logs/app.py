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
db_name = 'logs.db'
sql_file = "logs.sql"
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

@app.route('/clear', methods=(['GET']))
def clear():
    try:
        os.remove(db_name)
        global db_flag
        db_flag = False

    except Exception as e:
        pass
    return 'cleared'

@app.route('/add_log', methods=(['POST']))
def add_log():
    event = request.form.get('event')
    user = request.form.get('user')
    name = request.form.get('name')
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2})

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = "INSERT INTO Logs (event, username, name) VALUES (?, ?, ?);"
        cursor.execute(query, (event, user, name))

        conn.commit()
        conn.close()

        return json.dumps({'status': 1})

    except Exception as e:
        conn.close()
        return json.dumps({'status': 2})

@app.route('/view_log', methods=(['GET']))
def view_log():
    username = request.args.get('username')
    product = request.args.get('product')
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    jwt_username = payload.get('username')

    if jwt != calculate_jwt(jwt_username):
        return json.dumps({'status': 2, 'data': 'NULL'})

    if not((username == jwt_username) or (check_employee(jwt))):
        return json.dumps({'status': 3, 'data': 'NULL'})

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = "SELECT event, username, name FROM Logs WHERE username = ? ORDER BY sequence;" if username \
                    else "SELECT event, username, name FROM Logs WHERE name = ? ORDER BY sequence;"

        param = username if username else product
        cursor.execute(query, (param,))
        results = cursor.fetchall()

        data = {}
        for i in range(len(results)):
            data[i+1] = {'event': results[i][0], 'user': results[i][1], 'name': results[i][2]}

        conn.commit()
        conn.close()

        return json.dumps({'status': 1, 'data': data})

    except Exception as e:
        conn.close()

    return json.dumps({'status': 2, 'data': 'NULL'})

@app.route('/last_mod', methods=(['GET']))
def last_mod():
    product_name = request.args.get('product_name')
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2, 'last_mod': 'NULL'})

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = "SELECT username FROM Logs WHERE name = ? AND event = ? OR event = ? ORDER BY sequence DESC LIMIT 1;"
        params = (product_name, 'product_creation', 'product_edit')

        cursor.execute(query, params)
        last_mod = cursor.fetchone()

        conn.commit()
        conn.close()

        last_mod = last_mod[0] if last_mod else 'NULL'

        return json.dumps({'status': 1, 'last_mod': last_mod})

    except Exception as e:
        conn.close()

    return json.dumps({'status': 2, 'last_mod': 'NULL'})