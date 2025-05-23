import sqlite3
import os
import json
import hashlib
import base64
import hmac
import sys

import requests
from flask import Flask, request

app = Flask(__name__)
db_name = 'user.db'
sql_file = "user.sql"
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


def is_valid(password, first_name, last_name, username):
    valid = len(password) >= 8
    valid = valid and any([character.islower() for character in password])
    valid = valid and any([character.isupper() for character in password])
    valid = valid and any([character.isdigit() for character in password])
    valid = valid and first_name not in password
    valid = valid and last_name not in password
    valid = valid and username not in password

    return valid

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

@app.route('/create_user', methods=(['POST']))
def create_user():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    username = request.form.get('username')
    email_address = request.form.get('email_address')
    employee = 1 if request.form.get('employee') == 'True' else 0
    password = request.form.get('password')
    salt = request.form.get('salt')

    output = 'empty'
    if not is_valid(password, first_name, last_name, username):
        output = json.dumps({'status': 4, 'pass_hash': 'NULL'})
        return output

    password_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

    conn = get_db()
    try:
        cursor = conn.cursor()
        insert_query = "INSERT INTO Users VALUES (?, ?, ?, ?, ?, ?, ?);"
        cursor.execute(insert_query, (first_name, last_name, username, email_address,
                                      salt, password_hash, employee))

        conn.commit()
        conn.close()

        output = json.dumps({'status': 1, 'pass_hash': password_hash})
        add_to_log('user_creation', username, 'NULL', calculate_jwt(username))

    except sqlite3.IntegrityError as e:
        conn.close()
        if str(e) == "UNIQUE constraint failed: Users.username":
            output = json.dumps({'status': 2, 'pass_hash': 'NULL'})
        elif str(e) == "UNIQUE constraint failed: Users.email":
            output = json.dumps({'status': 3, 'pass_hash': 'NULL'})

    except Exception as e:
        conn.close()

    return output

@app.route('/login', methods=(['POST']))
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    output = 'empty'
    conn = get_db()
    try:
        cursor = conn.cursor()
        salt_query = "SELECT salt FROM Users WHERE username = ?;"
        cursor.execute(salt_query, (username,))
        salt = cursor.fetchone()

        if salt is None:
            conn.commit()
            conn.close()
            output = json.dumps({'status': 2, 'jwt': 'NULL'})
            return output

        password_hash_query = "SELECT current_password_hash FROM Users WHERE username = ?;"
        cursor.execute(password_hash_query, (username,))

        database_password = cursor.fetchone()
        password_hash = hashlib.sha256((password + salt[0]).encode('utf-8')).hexdigest()

        conn.commit()
        conn.close()

        if database_password[0] != password_hash:
            output = json.dumps({'status': 2, 'jwt': 'NULL'})
            return output

        output = json.dumps({'status': 1, 'jwt': calculate_jwt(username)})
        add_to_log('login', username, 'NULL', calculate_jwt(username))

    except Exception as e:
        conn.close()

    return output

@app.route('/check_employee', methods=(['POST']))
def check_employee():
    jwt = request.headers.get('Authorization')

    payload = json.loads((base64.urlsafe_b64decode((jwt.split('.')[1]).encode('utf-8'))).decode('utf-8'))
    username = payload.get('username')

    if jwt != calculate_jwt(username):
        return json.dumps({'status': 2})

    conn = get_db()
    try:
        cursor = conn.cursor()
        query = "SELECT isEmployee FROM Users WHERE username = ?;"

        cursor.execute(query, (username,))
        isEmployee = cursor.fetchone()

        if not isEmployee or isEmployee[0] != 1:
            conn.commit()
            conn.close()
            return json.dumps({'status': 2})

        conn.commit()
        conn.close()

    except Exception as e:
        conn.close()
        return json.dumps({'status': 2})

    return json.dumps({'status': 1})