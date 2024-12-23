# IO LOGIN (FOR ALL IO PROGRAMS) BACKEND PYTHON FILE
# https://mrle52rri4.execute-api.us-west-1.amazonaws.com/dev/api/v2/<enter_endpoint_details>

# To run program:  python3 io_login_api.py

# README:  if conn error make sure password is set properly in RDS PASSWORD section

# README:  Debug Mode may need to be set to False when deploying live (although it seems to be working through Zappa)

# README:  if there are errors, make sure you have all requirements are loaded
# pip3 install -r requirements.txt


import json
import os
from dotenv import load_dotenv
import requests
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.exceptions import BadRequest, NotFound
from datetime import datetime, date, timedelta
import pymysql
from decimal import Decimal
import string
import random
from random import randint
from hashlib import sha256, sha512
from flask_jwt_extended import create_access_token, create_refresh_token, JWTManager
import hashlib
from werkzeug.datastructures import FileStorage  # For file handling
from werkzeug.datastructures import ImmutableMultiDict
from io import BytesIO


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import json
import base64



# Using cryptograpghy
# AES_KEY = b'IO95120secretkey'  # 16 bytes
# BLOCK_SIZE = 16  # AES block size

load_dotenv()
AES_SECRET_KEY = os.getenv('AES_SECRET_KEY')
# print("AES Secret Key: ", AES_SECRET_KEY)
AES_KEY = AES_SECRET_KEY.encode('utf-8')
BLOCK_SIZE = int(os.getenv('BLOCK_SIZE'))
# print("Block Size: ", BLOCK_SIZE)


encrypt_flag = False

# Encrypt dictionary
def encrypt_dict(data_dict):
    try:
        print("In encrypt_dict: ", data_dict)
        # Convert dictionary to JSON string
        json_data = json.dumps(data_dict).encode()

        # Pad the JSON data
        padder = PKCS7(BLOCK_SIZE * 8).padder()
        padded_data = padder.update(json_data) + padder.finalize()

        # Generate a random initialization vector (IV)
        iv = os.urandom(BLOCK_SIZE)

        # Create a new AES cipher
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV and encrypted data, then Base64 encode
        encrypted_blob = base64.b64encode(iv + encrypted_data).decode()
        return encrypted_blob
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

# Decrypt dictionary
def decrypt_dict(encrypted_blob):
    print("Actual decryption started")
    try:
        # Base64 decode the encrypted blob
        encrypted_data = base64.b64decode(encrypted_blob)

        # Extract the IV (first BLOCK_SIZE bytes) and the encrypted content
        iv = encrypted_data[:BLOCK_SIZE]
        encrypted_content = encrypted_data[BLOCK_SIZE:]

        # Create a new AES cipher
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the encrypted content
        decrypted_padded_data = decryptor.update(encrypted_content) + decryptor.finalize()

        # Unpad the decrypted content
        unpadder = PKCS7(BLOCK_SIZE * 8).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Convert the JSON string back to a dictionary
        return json.loads(decrypted_data.decode())
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


app = Flask(__name__)
CORS(app)

# API
api = Api(app)


app.config['JWT_SECRET_KEY'] = 'secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
app.config['PROPAGATE_EXCEPTIONS'] = True
jwt = JWTManager(app)

# --------------- Mail Variables ------------------
# Mail username and password loaded in .env file
app.config['MAIL_USERNAME'] = "support@manifestmy.space"
app.config['MAIL_PASSWORD'] = "Support4MySpace"
app.config['MAIL_DEFAULT_SENDER'] = "support@manifestmy.space"

app.config["MAIL_SERVER"] = "smtp.mydomain.com"
app.config["MAIL_PORT"] = 465

app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True


# Set this to false when deploying to live application
# app.config["DEBUG"] = True
app.config["DEBUG"] = True

mail = Mail(app)


def connect(RDS_DB):
    global RDS_PW
    global RDS_HOST
    global RDS_PORT
    global RDS_USER

    print("Trying to connect to RDS (API v2)...")
    try:
        conn = pymysql.connect(
            host=os.getenv('RDS_HOST'),
            user=os.getenv('RDS_USER'),
            port=int(os.getenv('RDS_PORT')),
            passwd=os.getenv('RDS_PW'),
            db=RDS_DB,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
        )
    # try:
    #     conn = pymysql.connect(
    #         host=RDS_HOST,
    #         user=RDS_USER,
    #         port=RDS_PORT,
    #         passwd=RDS_PW,
    #         db=RDS_DB,
    #         cursorclass=pymysql.cursors.DictCursor,
    #     )
        print("Successfully connected to RDS. (API v2)")
        return conn
    except:
        print("Could not connect to RDS. (API v2)")
        raise Exception("RDS Connection failed. (API v2)")


# Disconnect from MySQL database (API v2)
def disconnect(conn):
    try:
        conn.close()
        print("Successfully disconnected from MySQL database. (API v2)")
    except:
        print("Could not properly disconnect from MySQL database. (API v2)")
        raise Exception("Failure disconnecting from MySQL database. (API v2)")


# Serialize JSON
def serializeResponse(response):
    try:
        # print("In Serialize JSON")
        for row in response:
            for key in row:
                if type(row[key]) is Decimal:
                    row[key] = float(row[key])
                elif type(row[key]) is date or type(row[key]) is datetime:
                    row[key] = row[key].strftime("%Y-%m-%d")
        # print("In Serialize JSON response", response)
        return response
    except:
        raise Exception("Bad query JSON")


def execute(sql, cmd, conn, skipSerialization=False):
    response = {}
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            if cmd == "get":
                result = cur.fetchall()

                response["message"] = "Successfully executed SQL query."
                # Return status code of 280 for successful GET request
                response["code"] = 280
                if not skipSerialization:
                    result = serializeResponse(result)
                response["result"] = result
            elif cmd == "post":
                conn.commit()
                response["message"] = "Successfully committed SQL command."
                # Return status code of 281 for successful POST request
                response["code"] = 281
            else:
                response[
                    "message"
                ] = "Request failed. Unknown or ambiguous instruction given for MySQL command."
                # Return status code of 480 for unknown HTTP method
                response["code"] = 480
    except:
        response["message"] = "Request failed, could not execute MySQL command."
        # Return status code of 490 for unsuccessful HTTP request
        response["code"] = 490
    finally:
        response["sql"] = sql
        return response


def sendEmail(recipient, subject, body):
    with app.app_context():

        msg = Message(
            sender="support@manifestmy.space",
            recipients=[recipient],
            subject=subject,
            body=str(body)
        )
        mail.send(msg)


def getBusinessProfileInfo(user, projectName):
    global encrypt_flag 
    if projectName == 'PM':
        response = {}
        conn = connect('pm')
        query = """SELECT b.*, e.employee_role
            FROM employees e LEFT JOIN businesses b ON e.business_uid = b.business_uid
            WHERE user_uid = \'""" + user['user_uid'] + """\'"""

        response = execute(query, "get", conn)
        return response
    elif projectName == "MYSPACE":
        encrypt_flag = True
        response = {}
        conn = connect('space')
        query = """SELECT business_uid, business_type, 
                employee_uid, employee_role FROM space.employees
            LEFT JOIN space.businessProfileInfo 
            ON employee_business_id = business_uid
                WHERE employee_user_id = \'""" + user['user_uid'] + """\'"""
        response = execute(query, "get", conn)
        if "result" not in response:
            response["result"] = None
        else:
            businesses = {
                'MAINTENANCE': {},
                'MANAGEMENT': {}
            }
            key_map = {
                'MAINTENANCE': {
                    'OWNER': 'business_owner_id',
                    'EMPLOYEE': 'business_employee_id'
                },
                'MANAGEMENT': {
                    'OWNER': 'business_owner_id',
                    'EMPLOYEE': 'business_employee_id' 
                }
            }
            for record in response["result"]:
                role_key = key_map[record['business_type']][record['employee_role']]
                businesses[record['business_type']].update({
                    role_key: record['employee_uid'],
                    'business_uid': record['business_uid']
                })
            response["result"] = businesses
        return response


def getTenantProfileInfo(user, projectName):
    global encrypt_flag 
    if projectName == 'PM':
        response = {}
        conn = connect('pm')
        query = """ SELECT tenant_id FROM tenantProfileInfo
                WHERE tenant_user_id = \'""" + user['user_uid'] + """\'"""

        response = execute(query, "get", conn)
        return response
    elif projectName == "MYSPACE":
        encrypt_flag = True
        response = {}
        conn = connect('space')
        query = """SELECT tenant_uid FROM tenantProfileInfo 
            WHERE tenant_user_id = \'""" + user['user_uid'] + """\'"""
        response = execute(query, "get", conn)
        if "result" not in response or len(response["result"]) == 0:
            response["result"] = ""
        else:
            response["result"] = response["result"][0]["tenant_uid"]
        return response
    
def getOwnerProfileInfo(user, projectName):
    global encrypt_flag 
    if projectName == 'MYSPACE':
        encrypt_flag = True
        response = {}
        conn = connect('space')
        query = """SELECT owner_uid FROM ownerProfileInfo 
            WHERE owner_user_id = \'""" + user['user_uid'] + """\'"""
        response = execute(query, "get", conn)
        if "result" not in response or len(response["result"]) == 0:
            response["result"] = ""
        else:
            response["result"] = response["result"][0]["owner_uid"]
        return response


def getHash(value):
    base = str(value).encode()
    return sha256(base).hexdigest()


def createSalt():
    return getHash(datetime.now())


def createHash(password, salt):
    return getHash(password+salt)


def createTokens(user, projectName):
    print('IN CREATETOKENS')

    businesses = getBusinessProfileInfo(user, projectName)['result']
    print("1")
    tenant_id = getTenantProfileInfo(user, projectName)['result']
    print("2")
    owner_id = getOwnerProfileInfo(user, projectName)['result']
    print("3")


    if not user.get('notifications'): user['notifications'] = "true"
    if not user.get('dark_mode'): user['dark_mode'] = "false"
    if not user.get('cookies'): user['cookies'] = "true"

    userInfo = {
        'user_uid': user['user_uid'],
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'phone_number': user['phone_number'],
        'email': user['email'],
        'role': user['role'],
        'google_auth_token': user['google_auth_token'],
        'businesses': businesses,
        'tenant_id': tenant_id,
        'owner_id': owner_id,
        'notifications': user['notifications'],
        'dark_mode': user['dark_mode'],
        'cookies': user['cookies'],
    }

    return {
        'access_token': create_access_token(userInfo),
        'refresh_token': create_refresh_token(userInfo),
        'user': userInfo
    }

def getUserByUID(uid, projectName):
    global encrypt_flag 
    if projectName == "MYSPACE":
        encrypt_flag = True
        conn = connect('space')
        # get user
        user_lookup_query = ("""
        SELECT * FROM space.users
        WHERE user_uid = \'""" + uid + """\';""")
        result = execute(user_lookup_query, "get", conn)
        if len(result['result']) > 0:
            return result['result'][0]

def getUserByEmail(email, projectName):
    global encrypt_flag 
    if projectName == "PM":
        conn = connect('pm')
        # get user
        user_lookup_query = ("""
        SELECT * FROM pm.users
        WHERE email = \'""" + email + """\';""")
        result = execute(user_lookup_query, "get", conn)
        if len(result['result']) > 0:
            return result['result'][0]
    elif projectName == "MYSPACE":
        encrypt_flag = True
        conn = connect('space')
        # get user
        user_lookup_query = ("""
        SELECT * FROM space.users
        WHERE email = \'""" + email + """\';""")
        result = execute(user_lookup_query, "get", conn)
        if len(result['result']) > 0:
            return result['result'][0]
    elif projectName == "NITYA":
        conn = connect('nitya')
        # get user
        user_lookup_query = ("""
        SELECT * FROM nitya.customers
        WHERE customer_email =\'""" + email + """\';""")
        result = execute(user_lookup_query, "get", conn)
        if len(result['result']) > 0:
            return result['result'][0]
    elif projectName == "SKEDUL":
        conn = connect('skedul')
        # get user
        user_lookup_query = ("""
        SELECT * FROM skedul.users
        WHERE user_email_id = \'""" + email + """\';""")
        result = execute(user_lookup_query, "get", conn)
        if len(result['result']) > 0:
            return result['result'][0]
    elif projectName == "FINDME":
        conn = connect('find_me')
        # get user
        user_lookup_query = ("""
        SELECT * FROM find_me.users
        WHERE email = \'""" + email + """\';""")
        result = execute(user_lookup_query, "get", conn)
        if len(result['result']) > 0:
            return result['result'][0]
    elif projectName == "MMU":
        conn = connect('mmu')
        # get user
        user_lookup_query = ("""
        SELECT * FROM mmu.users
        WHERE user_email_id = \'""" + email + """\';""")
        result = execute(user_lookup_query, "get", conn)
        # print("MMU result: ", result)
        if len(result['result']) > 0:
            # print("Before return: ", result['result'][0] )
            return result['result'][0]


def createUser(firstName, lastName, phoneNumber, email, password, role=None, email_validated=None, google_auth_token=None, google_refresh_token=None, social_id=None, access_expires_in=None, projectName=None):
    global encrypt_flag 
    if projectName == 'PM':
        conn = connect('pm')
        query = ["CALL pm.new_user_id;"]
        NewIDresponse = execute(query[0], "get", conn)

        newUserID = NewIDresponse["result"][0]["new_id"]
        passwordSalt = createSalt()
        passwordHash = createHash(password, passwordSalt)
        newUser = {
            'user_uid': newUserID,
            'first_name': firstName,
            'last_name': lastName,
            'phone_number': phoneNumber,
            'email': email,
            'password_salt': passwordSalt,
            'password_hash': passwordHash,
            'role': role,
            'google_auth_token': google_auth_token,
            'google_refresh_token': google_refresh_token,
            'social_id': social_id,
            'access_expires_in': access_expires_in
        }
        query = ("""
            INSERT INTO pm.users SET
                user_uid = \'""" + newUserID + """\',
                first_name = \'""" + firstName + """\',
                last_name = \'""" + lastName + """\',
                phone_number = \'""" + phoneNumber + """\',
                email = \'""" + email + """\',
                password_salt = \'""" + passwordSalt + """\',
                password_hash = \'""" + passwordHash + """\',
                role = \'""" + role + """\',
                google_auth_token = \'""" + google_auth_token + """\',
                google_refresh_token = \'""" + google_refresh_token + """\',
                social_id = \'""" + social_id + """\',
                access_expires_in = \'""" + access_expires_in + """\';
                    """)

        # print("PM Query: ", query)
        response = execute(query, "post", conn)
        # print("After PM Create User: ", response)
        return newUser
    elif projectName == 'MYSPACE':
        encrypt_flag = True
        conn = connect('space')
        query = ["CALL space.new_user_uid;"]
        NewIDresponse = execute(query[0], "get", conn)

        newUserID = NewIDresponse["result"][0]["new_id"]
        print("MySpace userID: ", newUserID)
        passwordSalt = createSalt()
        passwordHash = createHash(password, passwordSalt)
        newUser = {
            'user_uid': newUserID,
            'first_name': firstName,
            'last_name': lastName,
            'phone_number': phoneNumber,
            'email': email,
            'password_salt': passwordSalt,
            'password_hash': passwordHash,
            'role': role,
            'google_auth_token': google_auth_token,
            'google_refresh_token': google_refresh_token,
            'social_id': social_id,
            'access_expires_in': access_expires_in
        }
        query = ("""
            INSERT INTO space.users SET
                user_uid = \'""" + newUserID + """\',
                first_name = \'""" + firstName + """\',
                last_name = \'""" + lastName + """\',
                phone_number = \'""" + phoneNumber + """\',
                email = \'""" + email + """\',
                password_salt = \'""" + passwordSalt + """\',
                password_hash = \'""" + passwordHash + """\',
                role = \'""" + role + """\',
                google_auth_token = \'""" + google_auth_token + """\',
                google_refresh_token = \'""" + google_refresh_token + """\',
                social_id = \'""" + social_id + """\',
                access_expires_in = \'""" + access_expires_in + """\';
                    """)
        print("Myspace Query: ", query)
        response = execute(query, "post", conn)
        print("MYSPACE response: ", response)
        print("MYSPACE response code: ", response['code'])
        return (newUser, response['code'])
    elif projectName == 'FINDME':
        conn = connect('find_me')
        query = ["CALL find_me.new_user_id;"]
        NewIDresponse = execute(query[0], "get", conn)
        newUserID = NewIDresponse["result"][0]["new_id"]
        passwordSalt = createSalt()
        passwordHash = createHash(password, passwordSalt)

        newUser = {
            'user_uid': newUserID,
            'first_name': firstName,
            'last_name': lastName,
            'phone_number': phoneNumber,
            'email': email,
            'password_salt': passwordSalt,
            'password_hash': passwordHash,
            'role': role,
            'email_validated': email_validated,
            'google_auth_token': google_auth_token,
            'google_refresh_token': google_refresh_token,
            'social_id': social_id,
            'access_expires_in': access_expires_in
        }
        query = ("""
            INSERT INTO find_me.users SET
                 user_uid = \'""" + newUserID + """\',
                first_name = \'""" + firstName + """\',
                last_name = \'""" + lastName + """\',
                phone_number = \'""" + phoneNumber + """\',
                email = \'""" + email + """\',
                password_salt = \'""" + passwordSalt + """\',
                password_hash = \'""" + passwordHash + """\',
                role = \'""" + role + """\',
                email_validated = \'""" + email_validated + """\',
                google_auth_token = \'""" + str(google_auth_token) + """\',
                google_refresh_token = \'""" + str(google_refresh_token) + """\',
                social_id = \'""" + social_id + """\',
                access_expires_in = \'""" + str(access_expires_in) + """\';
                    """)

        response = execute(query, "post", conn)
        subject = "Email Verification Code"
        message = "Email Verification Code Sent " + email_validated
        # msg = Message(
        #     "Email Verification Code",
        #     sender="support@manifestmy.space",
        #     recipients=[email],
        # )
        # print(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        # msg.body = ("Email Verification Code Sent ")
        # # print('msg-bd----', msg.body)
        # mail.send(str(email_validated))
        # print('after mail send')
        sendEmail(email, subject, message)

        return newUser
    elif projectName == 'MMU':
        conn = connect('mmu')
        query = ["CALL mmu.new_user_uid;"]
        NewIDresponse = execute(query[0], "get", conn)

        newUserID = NewIDresponse["result"][0]["new_id"]
        print("MMU userID: ", newUserID)
        passwordSalt = createSalt()
        passwordHash = createHash(password, passwordSalt)
        newUser = {
            'user_uid': newUserID,
            'first_name': firstName,
            'last_name': lastName,
            'phone_number': phoneNumber,
            'email': email,
            'password_salt': passwordSalt,
            'password_hash': passwordHash,
            'role': role,
            'google_auth_token': google_auth_token,
            'google_refresh_token': google_refresh_token,
            'social_id': social_id,
            'access_expires_in': access_expires_in
        }
        query = ("""
            INSERT INTO mmu.users SET
                user_uid = \'""" + newUserID + """\',
                -- user_first_name = \'""" + firstName + """\',
                -- user_last_name = \'""" + lastName + """\',
                user_phone_number = \'""" + phoneNumber + """\',
                user_email_id = \'""" + email + """\',
                user_password_salt = \'""" + passwordSalt + """\',
                user_password_hash = \'""" + passwordHash + """\',
                -- user_role = \'""" + role + """\',
                user_google_auth_token = \'""" + google_auth_token + """\',
                user_google_refresh_token = \'""" + google_refresh_token + """\',
                user_social_id = \'""" + social_id + """\',
                user_access_expires_in = \'""" + access_expires_in + """\';
                    """)
        # print("MMU Query: ", query)
        response = execute(query, "post", conn)
        # print("MMU response: ", response)
        # print("MMU response code: ", response['code'])
        return (newUser, response['code'])


# Get the correct users for a project
class GetUsers(Resource):

    def get(self, projectName):
        response = {}
        global encrypt_flag 
        items = {}
        # Business Code sent in as a parameter from frontend
        print("business: ", projectName)
        if projectName == "PM":
            try:

                conn = connect('pm')
                query = ("""SELECT * FROM pm.users;""")
                items = execute(query, "get", conn)
                response["message"] = "Users from PM"
                response["result"] = items["result"]

            except:
                raise BadRequest(
                    "Request failed, please try again later."
                )
            finally:
                disconnect(conn)
        elif projectName == "MYSPACE": 
            encrypt_flag = True
            try:

                conn = connect('pm')
                query = ("""SELECT * FROM space.users;""")
                items = execute(query, "get", conn)
                response["message"] = "Users from MYSPACE"
                response["result"] = items["result"]

            except:
                raise BadRequest(
                    "Request failed, please try again later."
                )
            finally:
                disconnect(conn)
        elif projectName == "NITYA":
            try:

                conn = connect('nitya')
                query = ("""SELECT * FROM nitya.customers;""")
                items = execute(query, "get", conn)
                response["message"] = "Customers from Nitya"
                response["result"] = items["result"]

            except:
                raise BadRequest(
                    "Request failed, please try again later."
                )
            finally:
                disconnect(conn)
        elif projectName == "SKEDUL":
            try:

                conn = connect('skedul')
                query = ("""SELECT * FROM skedul.users;""")
                items = execute(query, "get", conn)
                response["message"] = "Users from SKEDUL"
                response["result"] = items["result"]

            except:
                raise BadRequest(
                    "Request failed, please try again later."
                )
            finally:
                disconnect(conn)
        elif projectName == "FINDME":
            try:

                conn = connect('find_me')
                query = ("""SELECT * FROM find_me.users;""")
                items = execute(query, "get", conn)
                response["message"] = "Users from FIND ME"
                response["result"] = items["result"]

            except:
                raise BadRequest(
                    "Request failed, please try again later."
                )
            finally:
                disconnect(conn)
        return response


class SetTempPassword(Resource):
    def get_random_string(self, stringLength=8):
        lettersAndDigits = string.ascii_letters + string.digits
        return "".join([random.choice(lettersAndDigits) for i in range(stringLength)])

    def post(self, projectName):
        response = {}
        global encrypt_flag 
        items = {}
        user_lookup = {}
        data = request.get_json(force=True)
        email = data['email']
        if projectName == "PM":
            conn = connect('pm')
            # get user
            user_lookup_query = ("""
            SELECT * FROM pm.users
            WHERE email = \'""" + email + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)

            # update table
            query_update = """
            UPDATE pm.users 
                SET 
                password_salt = \'""" + passwordSalt + """\',
                password_hash =  \'""" + passwordHash + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            # send email
            subject = "Email Verification"
            recipient = email
            body = (
                "Your temporary password is {}. Please use it to reset your password".format(
                    pass_temp)
            )
            sendEmail(recipient, subject, body)
            response['message'] = "A temporary password has been sent"

        elif projectName == "MYSPACE":
            encrypt_flag = True
            conn = connect('space')
            # get user
            user_lookup_query = ("""
            SELECT * FROM space.users
            WHERE email = \'""" + email + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)

            # update table
            query_update = """
            UPDATE space.users 
                SET 
                password_salt = \'""" + passwordSalt + """\',
                password_hash =  \'""" + passwordHash + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            # send email
            subject = "Email Verification"
            recipient = email
            body = (
                "Your temporary password is {}. Please use it to reset your password".format(
                    pass_temp)
            )
            sendEmail(recipient, subject, body)
            response['message'] = "A temporary password has been sent"

        elif projectName == "NITYA":
            conn = connect('nitya')
            # get user
            user_lookup_query = ("""
            SELECT * FROM nitya.customers
            WHERE customer_email =\'""" + email + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['customer_uid']

            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE nitya.customers 
                SET 
                password_salt = \'""" + passwordSalt + """\',
                password_hashed =  \'""" + passwordHash + """\'
            WHERE customer_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)

            # send email
            subject = "Email Verification"
            recipient = email
            body = (
                "Your temporary password is {}. Please use it to reset your password".format(
                    pass_temp)
            )
            sendEmail(recipient, subject, body)
            response['message'] = "A temporary password has been sent"

        elif projectName == "SKEDUL":
            conn = connect('skedul')
            # get user
            user_lookup_query = ("""
            SELECT * FROM skedul.users
            WHERE user_email_id = \'""" + email + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_unique_id']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE skedul.users 
                SET 
                password_salt = \'""" + passwordSalt + """\',
                password_hashed =  \'""" + passwordHash + """\'
            WHERE user_unique_id = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            # send email
            subject = "Email Verification"
            recipient = email
            body = (
                "Your temporary password is {}. Please use it to reset your password".format(
                    pass_temp)
            )
            sendEmail(recipient, subject, body)
            response['message'] = "A temporary password has been sent"

        elif projectName == "FINDME":
            conn = connect('find_me')
            # get user
            user_lookup_query = ("""
            SELECT * FROM find_me.users
            WHERE email = \'""" + email + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE find_me.users 
                SET 
                password_salt = \'""" + passwordSalt + """\',
                password_hash =  \'""" + passwordHash + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            # send email
            subject = "Email Verification"
            recipient = email
            body = (
                "Your temporary password is {}. Please use it to reset your password".format(
                    pass_temp)
            )
            sendEmail(recipient, subject, body)
            response['message'] = "A temporary password has been sent"

        elif projectName == "MMU":
            conn = connect('mmu')
            # get user
            user_lookup_query = ("""
            SELECT * FROM mmu.users
            WHERE user_email_id = \'""" + email + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE mmu.users 
                SET 
                user_password_salt = \'""" + passwordSalt + """\',
                user_password_hash =  \'""" + passwordHash + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            # send email
            subject = "Email Verification"
            recipient = email
            body = (
                "Your temporary password is {}. Please use it to reset your password".format(
                    pass_temp)
            )
            sendEmail(recipient, subject, body)
            response['message'] = "A temporary password has been sent"

        else:
            response['message'] = "Project Not Found"

        
        return response


class UpdateEmailPassword(Resource):
    def post(self, projectName):
        response = {}
        global encrypt_flag 
        data = request.get_json(force=True)
        user_uid = data['user_uid']
        if projectName == "PM":
            conn = connect('pm')
            # get user
            user_lookup_query = ("""
            SELECT * FROM pm.users
            WHERE user_uid = \'""" + data['id'] + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = "User UID doesn't exists"
                user_lookup['result'] = user_lookup['result']
                user_lookup['code'] = 404
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            salt = createSalt()
            password = createHash(data['password'], salt)
            # update table
            query_update = """
            UPDATE pm.users 
                SET 
                password_salt = \'""" + salt + """\',
                password_hash =  \'""" + password + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "MYSPACE":
            encrypt_flag = True
            conn = connect('space')
            # get user
            user_lookup_query = ("""
            SELECT * FROM space.users
            WHERE user_uid = \'""" + data['id'] + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = "User UID doesn't exists"
                user_lookup['result'] = user_lookup['result']
                user_lookup['code'] = 404
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            salt = createSalt()
            password = createHash(data['password'], salt)
            # update table
            query_update = """
            UPDATE space.users 
                SET 
                password_salt = \'""" + salt + """\',
                password_hash =  \'""" + password + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "NITYA":
            conn = connect('nitya')
            # get user
            user_lookup_query = ("""
            SELECT * FROM nitya.customers
            WHERE customer_uid = \'""" + data['id'] + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['customer_uid']

            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE nitya.customers 
                SET 
                password_salt = \'""" + salt + """\',
                password_hashed =  \'""" + password + """\'
            WHERE customer_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "SKEDUL":
            conn = connect('skedul')
            # get user
            user_lookup_query = ("""
            SELECT * FROM skedul.users
            WHERE user_unique_id = \'""" + data['id'] + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_unique_id']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE skedul.users 
                SET 
                password_salt = \'""" + salt + """\',
                password_hashed =  \'""" + password + """\'
            WHERE user_unique_id = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "FINDME":
            conn = connect('find_me')
            # get user
            user_lookup_query = ("""
            SELECT * FROM find_me.users
            WHERE user_uid = \'""" + data['id'] + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE find_me.users 
                SET 
                password_salt = \'""" + passwordSalt + """\',
                password_hash =  \'""" + passwordHash + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "MMU":
            conn = connect('mmu')
            # get user
            user_lookup_query = ("""
            SELECT * FROM mmu.users
            WHERE user_uid = \'""" + data['id'] + """\';""")
            user_lookup = execute(user_lookup_query, "get", conn)

            if not user_lookup['result']:
                user_lookup['message'] = 'No such email exists'
                return user_lookup
            user_uid = user_lookup['result'][0]['user_uid']
            # create password salt and hash
            pass_temp = self.get_random_string()
            passwordSalt = createSalt()
            passwordHash = createHash(pass_temp, passwordSalt)
            # update table
            query_update = """
            UPDATE mmu.users 
                SET 
                password_salt = \'""" + passwordSalt + """\',
                password_hash =  \'""" + passwordHash + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'
        return response


class AccountSalt(Resource):
    def post(self, projectName):
        print("In Account Salt POST")
        response = {}
        global encrypt_flag 
        items = {}
        data = request.get_json(force=True)
        if "encrypted_data" in data:
            encrypted_data = data["encrypted_data"]
            data = decrypt_dict(encrypted_data)

        # print("data: ", data)
        email = data["email"]

        if projectName == 'PM':
            conn = connect('pm')
            try:
                query = ("""
                SELECT * FROM pm.users WHERE email = \'""" + email + """\';
                    """)
                items = execute(query, "get", conn)

                if not items["result"]:
                    items["message"] = "Email doesn't exists"
                    items["code"] = 404
                    return items
                items['result'] = [{
                    "password_algorithm": "SHA256",
                    "password_salt": items['result'][0]['password_salt'],
                }]
                items["message"] = "SALT sent successfully"
                items["code"] = 200
                return items
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'MYSPACE':
            print("In Myspace Account Salt")
            encrypt_flag = True
            conn = connect('space')
            try:
                query = ("""
                SELECT * FROM space.users WHERE email = \'""" + email + """\';
                    """)
                items = execute(query, "get", conn)

                if not items["result"]:
                    items["message"] = "Email doesn't exists"
                    items["code"] = 404
                    return items
                items['result'] = [{
                    "password_algorithm": "SHA256",
                    "password_salt": items['result'][0]['password_salt'],
                }]
                items["message"] = "SALT sent successfully"
                items["code"] = 200
                return items
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'NITYA':
            conn = connect('nitya')
            try:

                query = ("""
                SELECT password_algorithm,
                        password_salt,
                        user_social_media
                FROM nitya.customers cus WHERE customer_email = \'""" + email + """\';
                    """)
                items = execute(query, "get", conn)

                if not items["result"]:
                    items["message"] = "Email doesn't exists"
                    items["code"] = 404
                    return items
                if items["result"][0]["user_social_media"] != "NULL":
                    items["message"] = (
                        """Social Signup exists. Use \'"""
                        + items["result"][0]["user_social_media"]
                        + """\' """
                    )
                    items["code"] = 401
                    return items
                items["message"] = "SALT sent successfully"
                items["code"] = 200
                return items

            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            try:
                query = ("""
                SELECT * FROM skedul.users WHERE user_email = \'""" + email + """\';
                    """)
                items = execute(query, "get", conn)

                if not items["result"]:
                    items["message"] = "Email doesn't exists"
                    items["code"] = 404
                    return items
                items['result'] = [{
                    "password_algorithm": "SHA256",
                    "password_salt": str(datetime.now()),
                }]
                items["message"] = "SALT sent successfully"
                items["code"] = 200
                return items
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'FINDME':
            conn = connect('find_me')
            try:
                query = ("""
                SELECT * FROM find_me.users WHERE email = \'""" + email + """\';
                    """)
                items = execute(query, "get", conn)

                if not items["result"]:
                    items["message"] = "Email doesn't exist"
                    items["code"] = 404
                    return items
                items['result'] = [{
                    "password_algorithm": "SHA256",
                    "password_salt": items['result'][0]['password_salt'],
                }]
                items["message"] = "SALT sent successfully"
                items["code"] = 200
                return items
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'MMU':
            conn = connect('mmu')
            try:
                query = ("""
                SELECT * FROM mmu.users WHERE user_email_id = \'""" + email + """\';
                    """)
                items = execute(query, "get", conn)

                if not items["result"]:
                    items["message"] = "Email doesn't exist"
                    items["code"] = 404
                    return items
                items['result'] = [{
                    "password_algorithm": "SHA256",
                    "password_salt": items['result'][0]['user_password_salt'],
                }]
                items["message"] = "SALT sent successfully"
                items["code"] = 200
                return items
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        return items


class Login(Resource):
    def post(self, projectName):
        response = {}
        global encrypt_flag 
        data = request.get_json(force=True)
        if "encrypted_data" in data:
            encrypted_data = data["encrypted_data"]
            data = decrypt_dict(encrypted_data)

        email = data["email"]
        password = data.get("password")

        if projectName == 'PM':
            conn = connect('pm')
            user = getUserByEmail(email, projectName)
            if user:
                if password == user['password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = createTokens(user, projectName)
                else:
                    response['message'] = 'Incorrect password'
                    response['code'] = 401
            else:
                response['message'] = 'Email not found'
                response['code'] = 404

        elif projectName == 'MYSPACE':
            encrypt_flag = True
            user = getUserByEmail(email, projectName)
            if user:
                if password == user['password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = createTokens(user, projectName)
                else:
                    response['message'] = 'Incorrect password'
                    response['code'] = 401
            else:
                response['message'] = 'Email not found'
                response['code'] = 404

        elif projectName == 'NITYA':
            conn = connect('nitya')
            user = getUserByEmail(email, projectName)
            if not user:
                response['message'] = 'Email not found'
                response['code'] = 404

            else:
                # checks if login was by social media
                if (
                    password
                    and user["user_social_media"] != "NULL"
                    and user["user_social_media"] != None
                ):
                    response["message"] = "Need to login by Social Media"
                    response["code"] = 401
                    return response

                # nothing to check
                elif (password is None
                      and user["user_social_media"] == "NULL"
                      ):
                    response["message"] = "Enter password else login from social media"
                    response["code"] = 405
                    return response

                # compare passwords if user_social_media is false
                elif (
                    user["user_social_media"] == "NULL"
                    or user["user_social_media"] == None
                ) and password is not None:

                    if user["password_hashed"] != password:
                        user["message"] = "Wrong password"
                        user["result"] = ""
                        user["code"] = 406
                        return user

                    if ((user["email_verified"]) == "0") or (
                        user["email_verified"] == "FALSE"
                    ):
                        response["message"] = "Account need to be verified by email."
                        response["code"] = 407
                        return response
                else:
                    string = " Cannot compare the password or social_id while log in. "

                    response["message"] = string
                    response["code"] = 500
                    return response
                del user["password_hashed"]
                del user["email_verified"]

                query = (
                    "SELECT * from nitya.customers WHERE customer_email = '"
                    + email
                    + "';"
                )
                items = execute(query, "get", conn)
                items["message"] = "Authenticated successfully."
                items["code"] = 200
                return items

        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            user = getUserByEmail(email, projectName)
            if user:
                if password == user['password_hashed']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                else:
                    response['message'] = 'Incorrect password'
                    response['code'] = 401
            else:
                response['message'] = 'Email not found'
                response['code'] = 404

        elif projectName == 'FINDME':
            conn = connect('find_me')
            user = getUserByEmail(email, projectName)
            if user:
                if password == user['password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = user
                else:
                    response['message'] = 'Incorrect password'
                    response['code'] = 401
            else:
                response['message'] = 'Email not found'
                response['code'] = 404

        elif projectName == 'MMU':
            # print("In MMU: ", projectName)
            # print("Email: ", email, password)
            conn = connect('mmu')
            user = getUserByEmail(email, projectName)
            # print("\n",user['user_password_hash'])
            if user:
                if password == user['user_password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = user
                else:
                    response['message'] = 'Incorrect password'
                    response['code'] = 401
            else:
                response['message'] = 'Email not found'
                response['code'] = 404
            
        else:
            response['message'] = 'Project not found'


        return response


class CreateAccount(Resource):
    def post(self, projectName):
        print("In Create Account POST")
        response = {}
        global encrypt_flag 
        if projectName == 'PM':
            conn = connect('pm')
            data = request.get_json()
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            phoneNumber = data.get('phone_number')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role')
            user = getUserByEmail(email, projectName)
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber,
                                  email, password, role, '', '', '', '', '', 'PM')
                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = createTokens(user, projectName)
            return response
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            print("In MySpace")
            data = request.get_json()
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            phoneNumber = data.get('phone_number')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role')
            user = getUserByEmail(email, projectName)
            if user:
                print("In Myspace User: ", user)
                print("In Myspace User ID: ", user['user_uid'])
                print("In Myspace User ID: ", user['role'])
                response['message'] = 'User already exists'
                response['user_uid'] = user['user_uid']
                response['user_roles'] = user['role']
            else:
                user = createUser(firstName, lastName, phoneNumber,
                                  email, password, role, '', '', '', '', '', 'MYSPACE')
                # response['user'] = user[0]
                print("In MySpace: ", user)
                response['message'] = 'Signup success'
                print("User 0: ", user[0])
                print("User 1: ", user[1])
                response['code'] = user[1]
                response['result'] = createTokens(user[0], projectName)
            return response
        elif projectName == 'NITYA':
            conn = connect('nitya')
            items = []
            try:
                data = request.get_json(force=True)
                email = data["email"]
                firstName = data["first_name"]
                lastName = data["last_name"]
                phone = data["phone_number"]
                address = data["address"]
                unit = data["unit"] if data.get("unit") is not None else "NULL"
                social_id = (
                    data["social_id"] if data.get(
                        "social_id") is not None else "NULL"
                )
                city = data["city"]
                state = data["state"]
                zip_code = data["zip_code"]
                latitude = data["latitude"]
                longitude = data["longitude"]
                referral = data["referral_source"]
                role = data["role"]
                cust_id = data["cust_id"] if data.get(
                    "cust_id") is not None else "NULL"

                if (
                    data.get("social") is None
                    or data.get("social") == "FALSE"
                    or data.get("social") == False
                    or data.get("social") == "NULL"
                ):
                    social_signup = False
                else:
                    social_signup = True

                get_user_id_query = "CALL new_customer_uid();"
                NewUserIDresponse = execute(get_user_id_query, "get", conn)

                if NewUserIDresponse["code"] == 490:
                    string = " Cannot get new User id. "
                    response["message"] = "Internal Server Error."
                    return response, 500
                NewUserID = NewUserIDresponse["result"][0]["new_id"]

                if social_signup == False:

                    salt = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")

                    password = sha512(
                        (data["password"] + salt).encode()).hexdigest()
                    algorithm = "SHA512"
                    mobile_access_token = "NULL"
                    mobile_refresh_token = "NULL"
                    user_access_token = "NULL"
                    user_refresh_token = "NULL"
                    user_social_signup = "NULL"
                else:

                    mobile_access_token = data["mobile_access_token"]
                    mobile_refresh_token = data["mobile_refresh_token"]
                    user_access_token = data["user_access_token"]
                    user_refresh_token = data["user_refresh_token"]
                    salt = "NULL"
                    password = "NULL"
                    algorithm = "NULL"
                    user_social_signup = data["social"]

                if cust_id != "NULL" and cust_id:

                    NewUserID = cust_id

                    query = (
                        """
                            SELECT user_access_token, user_refresh_token, mobile_access_token, mobile_refresh_token
                            FROM nitya.customers
                            WHERE customer_uid = \'"""
                        + cust_id
                        + """\';
                        """
                    )
                    it = execute(query, "get", conn)

                    if it["result"][0]["user_access_token"] != "FALSE":
                        user_access_token = it["result"][0]["user_access_token"]

                    if it["result"][0]["user_refresh_token"] != "FALSE":
                        user_refresh_token = it["result"][0]["user_refresh_token"]

                    if it["result"][0]["mobile_access_token"] != "FALSE":
                        mobile_access_token = it["result"][0]["mobile_access_token"]

                    if it["result"][0]["mobile_refresh_token"] != "FALSE":
                        mobile_refresh_token = it["result"][0]["mobile_refresh_token"]

                    customer_insert_query = [
                        """
                            UPDATE nitya.customers
                            SET
                            customer_created_at = \'"""
                        + (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
                        + """\',
                            customer_first_name = \'"""
                        + firstName
                        + """\',
                            customer_last_name = \'"""
                        + lastName
                        + """\',
                            customer_phone_num = \'"""
                        + phone
                        + """\',
                            customer_address = \'"""
                        + address
                        + """\',
                            customer_unit = \'"""
                        + unit
                        + """\',
                            customer_city = \'"""
                        + city
                        + """\',
                            customer_state = \'"""
                        + state
                        + """\',
                            customer_zip = \'"""
                        + zip_code
                        + """\',
                            customer_lat = \'"""
                        + latitude
                        + """\',
                            customer_long = \'"""
                        + longitude
                        + """\',
                            password_salt = \'"""
                        + salt
                        + """\',
                            password_hashed = \'"""
                        + password
                        + """\',
                            password_algorithm = \'"""
                        + algorithm
                        + """\',
                            referral_source = \'"""
                        + referral
                        + """\',
                            role = \'"""
                        + role
                        + """\',
                            user_social_media = \'"""
                        + user_social_signup
                        + """\',
                            social_timestamp  =  DATE_ADD(now() , INTERVAL 14 DAY)
                            WHERE customer_uid = \'"""
                        + cust_id
                        + """\';
                        """
                    ]

                else:

                    # check if there is a same customer_id existing
                    query = (
                        """
                            SELECT customer_email FROM nitya.customers
                            WHERE customer_email = \'"""
                        + email
                        + "';"
                    )

                    items = execute(query, "get", conn)
                    if items["result"]:

                        items["result"] = ""
                        items["code"] = 409
                        items["message"] = "Email address has already been taken."

                        return items

                    if items["code"] == 480:

                        items["result"] = ""
                        items["code"] = 480
                        items["message"] = "Internal Server Error."
                        return items

                    # write everything to database
                    customer_insert_query = [
                        """
                            INSERT INTO nitya.customers
                            (
                                customer_uid,
                                customer_created_at,
                                customer_first_name,
                                customer_last_name,
                                customer_phone_num,
                                customer_email,
                                customer_address,
                                customer_unit,
                                customer_city,
                                customer_state,
                                customer_zip,
                                customer_lat,
                                customer_long,
                                password_salt,
                                password_hashed,
                                password_algorithm,
                                referral_source,
                                role,
                                user_social_media,
                                user_access_token,
                                social_timestamp,
                                user_refresh_token,
                                mobile_access_token,
                                mobile_refresh_token,
                                social_id
                            )
                            VALUES
                            (

                                \'"""
                        + NewUserID
                        + """\',
                                \'"""
                        + (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
                        + """\',
                                \'"""
                        + firstName
                        + """\',
                                \'"""
                        + lastName
                        + """\',
                                \'"""
                        + phone
                        + """\',
                                \'"""
                        + email
                        + """\',
                                \'"""
                        + address
                        + """\',
                                \'"""
                        + unit
                        + """\',
                                \'"""
                        + city
                        + """\',
                                \'"""
                        + state
                        + """\',
                                \'"""
                        + zip_code
                        + """\',
                                \'"""
                        + latitude
                        + """\',
                                \'"""
                        + longitude
                        + """\',
                                \'"""
                        + salt
                        + """\',
                                \'"""
                        + password
                        + """\',
                                \'"""
                        + algorithm
                        + """\',
                                \'"""
                        + referral
                        + """\',
                                \'"""
                        + role
                        + """\',
                                \'"""
                        + user_social_signup
                        + """\',
                                \'"""
                        + user_access_token
                        + """\',
                                DATE_ADD(now() , INTERVAL 14 DAY),
                                \'"""
                        + user_refresh_token
                        + """\',
                                \'"""
                        + mobile_access_token
                        + """\',
                                \'"""
                        + mobile_refresh_token
                        + """\',
                                \'"""
                        + social_id
                        + """\');"""
                    ]
                items = execute(customer_insert_query[0], "post", conn)

                if items["code"] != 281:
                    items["result"] = ""
                    items["code"] = 480
                    items["message"] = "Error while inserting values in database"

                    return items

                items["result"] = {
                    "first_name": firstName,
                    "last_name": lastName,
                    "customer_uid": NewUserID,
                    "access_token": user_access_token,
                    "refresh_token": user_refresh_token,
                    "access_token": mobile_access_token,
                    "refresh_token": mobile_refresh_token,
                    "social_id": social_id,
                }
                items["message"] = "Signup successful"
                items["code"] = 200

            except:
                if "NewUserID" in locals():
                    execute(
                        """DELETE FROM customers WHERE customer_uid = '"""
                        + NewUserID
                        + """';""",
                        "post",
                        conn,
                    )
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            timestamp = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
            try:
                data = request.get_json(force=True)
                email_id = data["email_id"]
                password = data["password"]
                first_name = data["first_name"]
                last_name = data["last_name"]
                time_zone = data["time_zone"]

                user_id_response = execute(
                    """SELECT user_unique_id FROM users
                                                WHERE user_email_id = \'"""
                    + email_id
                    + """\';""",
                    "get",
                    conn,
                )

                if len(user_id_response["result"]) > 0:
                    response["message"] = "User already exists"

                else:

                    salt = os.urandom(32)

                    dk = hashlib.pbkdf2_hmac(
                        "sha256", password.encode("utf-8"), salt, 100000, dklen=128
                    )
                    key = (salt + dk).hex()

                    user_id_response = execute(
                        "CAll get_user_id;", "get", conn)
                    new_user_id = user_id_response["result"][0]["new_id"]

                    execute(
                        """INSERT INTO users
                            SET user_unique_id = \'"""
                        + new_user_id
                        + """\',
                                user_timestamp = \'"""
                        + timestamp
                        + """\',
                                user_email_id  = \'"""
                        + email_id
                        + """\',
                                user_first_name = \'"""
                        + first_name
                        + """\',
                                user_last_name = \'"""
                        + last_name
                        + """\',
                                password_hashed = \'"""
                        + key
                        + """\',
                                time_zone = \'"""
                        + time_zone
                        + """\';""",
                        "post",
                        conn,
                    )

                    response["message"] = "successful"
                    response["result"] = new_user_id

                return response, 200
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'FINDME':
            conn = connect('find_me')
            data = request.get_json()
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            phoneNumber = data.get('phone_number')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role')
            user = getUserByEmail(email, projectName)
            email_validated = str(randint(100, 999))
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber,
                                  email, password, role, email_validated, '', '', '', '', 'FINDME')

                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = user
            return response
        elif projectName == 'MMU':
            print("In MMU Create Account")
            conn = connect('mmu')
            data = request.get_json()
            print("MMU json data: ", data)
            firstName = "" # data.get('first_name')
            lastName = "" # data.get('last_name')
            phoneNumber = data.get('phone_number')
            email = data.get('email')
            password = data.get('password')
            # role = data.get('role')
            user = getUserByEmail(email, projectName)
            # email_validated = str(randint(100, 999))
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber,
                                  email, password, '', '', '', '', '', '', 'MMU')

                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = user
            return response
        
    def put(self, projectName):
        print(" In createAccount - PUT")
        response = {}
        global encrypt_flag 
        if projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space')            
            data = request.get_json()            

            if "user_uid" in data:
                userUID = data.get('user_uid')
                firstName = data.get('first_name')
                lastName = data.get('last_name')
                phoneNumber = data.get('phone_number')
                email = data.get('email')
                password = data.get('password')
                role = data.get('role')
                
                # create password salt and hash                
                passwordSalt = createSalt()
                passwordHash = createHash(password, passwordSalt)

                # update table
                query_update = """
                UPDATE space.users 
                    SET 
                    first_name = \'""" + firstName + """\',
                    last_name = \'""" + lastName + """\',
                    phone_number = \'""" + phoneNumber + """\',
                    email = \'""" + email + """\',
                    role = \'""" + role + """\',
                    password_salt = \'""" + passwordSalt + """\',
                    password_hash =  \'""" + passwordHash + """\'
                WHERE user_uid = \'""" + userUID + """\' """

                items = execute(query_update, "post", conn)

                user = {
                    'user_uid': userUID,
                    'first_name': firstName,
                    'last_name': lastName,
                    'phone_number': phoneNumber,
                    'email': email,
                    'password_salt': passwordSalt,
                    'password_hash': passwordHash,
                    'role': role,
                    'google_auth_token': None,
                    'google_refresh_token': None,
                    'social_id': None,
                    'access_expires_in': None
                }

                response['message'] = 'User details updated'
                response['code'] = 200
                response['result'] = createTokens(user, projectName)

                return response


            else:
                return "ERROR - user_id missing"


            
        


class CheckEmailValidationCode(Resource):
    def post(self, projectName):
        response = {}
        items = {}
        cus_id = {}
        if projectName == 'FINDME':
            try:
                conn = connect('find_me')
                data = request.get_json(force=True)

                user_uid = data["user_uid"]
                code = data["code"]

                get_verification_code_query = '''
                                SELECT email_validated FROM find_me.users WHERE user_uid=\'''' + user_uid + '''\'
                                '''

                validation = execute(get_verification_code_query, "get", conn)

                # If for some reason we can't find a user in the table with the given user_uid....
                if len(validation["result"]) == 0:
                    response["message"] = "No user has been found for the following user_uid. " \
                        "Perhaps you have entered an invalid user_uid, " \
                        "or the endpoint to createNewUsers is broken"
                    return response, 200

                # If we do find such a user,
                # we will cross-examine the code they have typed in against what we have stored in the database.
                # If it matches --> hooray! We set the email_validated of that user to true.
                # If it DOES NOT match --> whoops! They typed in a bad code.

                if validation["result"][0]["email_validated"] == "TRUE":
                    response["message"] = "User Email for this specific user has already been verified." \
                        " No need for a code! :)"
                    response["email_validated_status"] = "TRUE"

                elif validation["result"][0]["email_validated"] == "FALSE":
                    response["message"] = "You need to generate a code for this user before you verify it."
                    response["email_validated_status"] = "FALSE"

                elif validation["result"][0]["email_validated"] == code:
                    set_code_query = '''
                                    UPDATE find_me.users
                                    SET email_validated =\'''' + "TRUE" + '''\'
                                    WHERE user_uid=\'''' + user_uid + '''\'
                                    '''
                    verification = execute(set_code_query, "post", conn)
                    response["message"] = "User Email Verification Code has been validated. Have fun!"
                    response["email_validated_status"] = "TRUE"

                else:
                    response["message"] = "Invalid Verification Code." \
                        "The code provided does not match what we have in the database"
                    response["email_validated_status"] = "..."

                return response, 200
            except:
                raise BadRequest(
                    "Validate Email Verification Code Request Failed. Try again later. :(")
            finally:
                disconnect(conn)


class UpdateUser(Resource):
    def put(self, projectName):
        response = {}
        items = {}
        cus_id = {}
        if projectName == 'FINDME':
            try:
                conn = connect('find_me')
                data = request.get_json(force=True)
                user_uid = data.get('user_uid')
                firstName = data.get('first_name')
                lastName = data.get('last_name')
                phoneNumber = data.get('phone_number')

                query = """ UPDATE find_me.users 
                            SET
                            first_name = \'""" + firstName + """\',
                            last_name = \'""" + lastName + """\',
                            phone_number = \'""" + phoneNumber + """\'
                            WHERE user_uid = \'""" + user_uid + """\'; """

                items = execute(query, "post", conn)

                response["message"] = "Successfully executed SQL query."
                response['data'] = user_uid
                return response
            except:
                raise BadRequest(
                    "Update Request failed, please try again later")
            finally:
                disconnect(conn)


class UpdateUserByUID(Resource):
    def put(self, projectName):
        response = {}
        global encrypt_flag 
        try:
            if projectName == 'MYSPACE':
                encrypt_flag = True
                conn = connect('space')
                data = request.get_json()
                if data.get('user_uid') is None:
                    raise BadRequest("Request failed, no UID in payload.")
                user_uid = data.pop('user_uid')
                if not data:
                    raise BadRequest("Request failed, no fields to update.")
                fields_to_update = []
                for key, value in data.items():
                    fields_to_update.append(f"{key} = \'{value}\'")
                fields_to_update_str = " AND ".join(fields_to_update)
                query = "UPDATE users SET " + fields_to_update_str + \
                    " WHERE user_uid = \'" + user_uid + "\';"
                response = execute(query, "post", conn)
        except Exception as e:
            print("Exception while updating user: ", e)
            raise
        return response, 200

#  updating access token if expired


class UpdateAccessToken(Resource):
    def post(self, projectName, user_id,):
        print("In UpdateAccessToken")
        response = {}
        global encrypt_flag 
        items = {}
        data = request.get_json(force=True)
        google_auth_token = data["google_auth_token"]
        if projectName == 'PM':
            conn = connect('pm')

            query = """UPDATE pm.users
                SET google_auth_token = \'""" + google_auth_token + """\'
                WHERE user_uid = \'""" + user_id + """\' """
            response = execute(query, "post", conn)

            return response, 200
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space')

            query = """UPDATE space.users
                SET google_auth_token = \'""" + google_auth_token + """\'
                WHERE user_uid = \'""" + user_id + """\' """
            response = execute(query, "post", conn)

            return response, 200
        elif projectName == 'NITYA':
            conn = connect('nitya')
            query = """UPDATE nitya.customers
                       SET user_access_token = \'""" + google_auth_token + """\'
                       WHERE customer_uid = \'""" + user_id + """\';
                        """
            response = execute(query, "post", conn)
            return response, 200
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            query = """UPDATE skedul.users 
                        SET  google_auth_token = \'""" + google_auth_token + """\'
                        WHERE user_unique_id = \'""" + user_id + """\';
                        """
            response = execute(query, "post", conn)
            return response, 200
        elif projectName == 'FINDME':
            conn = connect('find_me')
            query = """UPDATE find_me.users
                SET google_auth_token = \'""" + google_auth_token + """\'
                WHERE user_uid = \'""" + user_id + """\' """
            response = execute(query, "post", conn)
            return response
# get user tokens


class UserToken(Resource):
    def get(self, projectName, user_email_id):
        print("In usertoken")
        response = {}
        global encrypt_flag 
        items = {}
        if projectName == 'PM':
            conn = connect('pm')
            query = (
                """SELECT user_uid
                                , email
                                , google_auth_token
                                , google_refresh_token
                        FROM
                        users WHERE email = \'"""
                + user_email_id
                + """\';"""
            )
            response = execute(query, 'get', conn)

            return response, 200
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space')
            query = (
                """SELECT user_uid
                                , email
                                , google_auth_token
                                , google_refresh_token
                        FROM
                        space.users WHERE email = \'"""
                + user_email_id
                + """\';"""
            )
            response = execute(query, 'get', conn)

            return response, 200
        elif projectName == 'NITYA':
            conn = connect('nitya')
            query = (
                """SELECT customer_uid
                                , customer_email
                                , user_access_token
                                , user_refresh_token
                        FROM
                        customers WHERE customer_email = \'"""
                + user_email_id
                + """\';"""
            )
            response = execute(query, 'get', conn)
            response["message"] = "successful"
            response["customer_uid"] = items["result"][0]["customer_uid"]
            response["customer_email"] = items["result"][0]["customer_email"]
            response["user_access_token"] = items["result"][0]["user_access_token"]
            response["user_refresh_token"] = items["result"][0][
                "user_refresh_token"
            ]

            return response, 200
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            query = (
                """SELECT user_unique_id
                                , user_email
                                , google_auth_token
                                , google_refresh_token
                        FROM
                        users WHERE user_email = \'"""
                + user_email_id
                + """\';"""
            )

            response = execute(query, 'get', conn)
            response["message"] = "successful"
            response["user_unique_id"] = items["result"][0]["user_unique_id"]
            response["user_email_id"] = items["result"][0]["user_email_id"]
            response["google_auth_token"] = items["result"][0]["google_auth_token"]
            response["google_refresh_token"] = items["result"][0][
                "google_refresh_token"
            ]

            return response, 200
        elif projectName == 'FINDME':
            conn = connect('find_me')
            query = (
                """SELECT user_uid
                                , email
                                , google_auth_token
                                , google_refresh_token
                        FROM
                        users WHERE email = \'"""
                + user_email_id
                + """\';"""
            )
            response = execute(query, 'get', conn)

            return response, 200
        elif projectName == 'SF':
            conn = connect('sf')
            query = (
                """SELECT customer_uid
                                , customer_email
                                , user_access_token
                                , user_refresh_token
                                , social_id
                        FROM
                        sf.customers WHERE customer_email = \'"""
                + user_email_id
                + """\';"""
            )
            response = execute(query, 'get', conn)

            return response, 200


class UserDetails(Resource):
    def get(self, projectName, user_id):
        print("In userDetails")
        response = {}
        global encrypt_flag 
        items = {}
        if projectName == 'PM':
            conn = connect('pm')
            if user_id[0] == '1':
                query = """SELECT 
                user_uid
                , email
                , first_name
                , last_name
                , google_auth_token
                , google_refresh_token FROM users WHERE user_uid = \'""" + user_id + """\' """

                response = execute(query, 'get', conn)

            elif user_id[0] == '3':
                query = """SELECT 
                user_uid
                , email
                , first_name
                , last_name
                , google_auth_token
                , google_refresh_token FROM tenantProfileInfo t
                                    LEFT JOIN
                                    users u
                                     ON t.tenant_user_id = u.user_uid WHERE tenant_id = \'""" + user_id + """\' """

                response = execute(query, 'get', conn)

            else:
                query = """ SELECT business_uid
                                    , business_email
                                    , business_name FROM businesses WHERE business_uid = \'""" + user_id + """\' """
                business_email = execute(query, 'get', conn)
                query = """SELECT user_uid
                                    , email
                                    , first_name
                                    , last_name
                                    , google_auth_token
                                    , google_refresh_token FROM users WHERE email = \'""" + business_email['result'][0]['business_email'] + """\' """
                response = execute(query, 'get', conn)
            return response
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space')
            if user_id[0] == '1':
                query = """SELECT 
                user_uid
                , email
                , first_name
                , last_name
                , google_auth_token
                , google_refresh_token FROM space.users WHERE user_uid = \'""" + user_id + """\' """

                response = execute(query, 'get', conn)

            elif user_id[0] == '3':
                query = """SELECT 
                user_uid
                , email
                , first_name
                , last_name
                , google_auth_token
                , google_refresh_token FROM space.tenantProfileInfo t
                                    LEFT JOIN
                                    space.users u
                                     ON t.tenant_user_id = u.user_uid WHERE tenant_id = \'""" + user_id + """\' """

                response = execute(query, 'get', conn)

            else:
                query = """ SELECT business_uid
                                    , business_email
                                    , business_name FROM space.businessProfileInfo WHERE business_uid = \'""" + user_id + """\' """
                business_email = execute(query, 'get', conn)
                query = """SELECT user_uid
                                    , email
                                    , first_name
                                    , last_name
                                    , google_auth_token
                                    , google_refresh_token FROM space.users WHERE email = \'""" + business_email['result'][0]['business_email'] + """\' """
                response = execute(query, 'get', conn)
            return response
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            query = None

            query = (
                """SELECT user_unique_id
                                , user_email_id
                                , user_first_name
                                , user_last_name
                                , google_auth_token
                                , google_refresh_token
                        FROM
                        users WHERE user_unique_id = \'"""
                + user_id
                + """\';"""
            )

            items = execute(query, "get", conn)
            response["message"] = "successful"
            response["user_unique_id"] = items["result"][0]["user_unique_id"]
            response["user_first_name"] = items["result"][0]["user_first_name"]
            response["user_last_name"] = items["result"][0]["user_last_name"]
            response["user_email_id"] = items["result"][0]["user_email_id"]
            response["google_auth_token"] = items["result"][0]["google_auth_token"]
            response["google_refresh_token"] = items["result"][0][
                "google_refresh_token"
            ]

            return response, 200
        elif projectName == 'FINDME':
            conn = connect('find_me')
            query = """SELECT 
                user_uid
                , email
                , first_name
                , last_name
                , phone_number
                , google_auth_token
                , google_refresh_token FROM users u
                WHERE user_uid = \'""" + user_id + """\' """

            response = execute(query, 'get', conn)
            return response


class UserDetailsByEmail(Resource):
    def get(self, projectName, email_id):
        print("In userDetails")
        response = {}
        items = {}
        if projectName == 'FINDME':
            conn = connect('find_me')
            query = """SELECT 
                user_uid
                , email
                , first_name
                , last_name
                , phone_number
                , google_auth_token
                , google_refresh_token FROM users u
                WHERE email = \'""" + email_id + """\' """

            response = execute(query, 'get', conn)
            return response


class GetEmailId(Resource):
    def get(self, projectName, email_id):
        print("In GetEmailID")
        response = {}
        items = {}
        if projectName == 'NITYA':
            conn = connect('nitya')
            emails = execute(
                """SELECT customer_email from customers where customer_email = \'""" + email_id + """\';""", 'get', conn)
            if len(emails['result']) > 0:
                response['message'] = emails['result'][0]['customer_email']
            else:
                response['message'] = 'User ID doesnt exist'

            return response, 200
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            try:
                emails = execute(
                    """SELECT user_email_id, user_unique_id from users where user_email_id = \'"""
                    + email_id
                    + """\';""",
                    "get",
                    conn,
                )
                if len(emails["result"]) > 0:
                    response["message"] = "User EmailID exists"
                    response["result"] = emails["result"][0]["user_unique_id"]
                else:
                    response["message"] = "User EmailID doesnt exist"

                return response, 200
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)


# creating new user social
class UserSocialSignUp(Resource):
    def post(self, projectName):
        print("In UserSocialSignUp - POST")
        response = {}
        global encrypt_flag 
        items = {}
        if projectName == 'PM':
            conn = connect('pm')
            data = request.get_json(force=True)

            email = data.get('email')
            phoneNumber = data.get('phone_number')
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            role = data.get('role')
            google_auth_token = data.get('google_auth_token')
            google_refresh_token = data.get('google_refresh_token')
            social_id = data.get('social_id')
            access_expires_in = data.get('access_expires_in')
            password = data.get('password')
            user = getUserByEmail(email, projectName)
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber, email, password, role, '',
                                  google_auth_token, google_refresh_token, social_id, access_expires_in, 'PM')
                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = createTokens(user, projectName)
            return response
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            data = request.get_json(force=True)

            email = data.get('email')
            phoneNumber = data.get('phone_number')
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            role = data.get('role')
            google_auth_token = data.get('google_auth_token')
            google_refresh_token = data.get('google_refresh_token')
            social_id = data.get('social_id')
            access_expires_in = data.get('access_expires_in')
            password = data.get('password')
            user = getUserByEmail(email, projectName)
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber, email, password, role, '',
                                  google_auth_token, google_refresh_token, social_id, access_expires_in, 'MYSPACE')
                response['message'] = 'Signup success'
                response['code'] = user[1]
                response['result'] = createTokens(user[0], projectName)
            return response
        elif projectName == 'NITYA':
            conn = connect('nitya')
            try:
                data = request.get_json(force=True)

                ts = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")

                customer_email = data['customer_email']
                customer_first_name = data['customer_first_name']
                customer_last_name = data['customer_last_name']
                customer_phone_num = data['customer_phone_num']
                role = data["role"]
                user_social_media = data["user_social_media"]
                user_access_token = data["user_access_token"]
                social_id = data["social_id"]
                user_refresh_token = data["user_refresh_token"]
                access_expires_in = data["access_expires_in"]

                cust_id_response = execute("""SELECT customer_uid, password_hashed FROM customers
                                                WHERE customer_email = \'""" + customer_email + """\';""", 'get', conn)

                if len(cust_id_response['result']) > 0:

                    response['message'] = "Email ID already exists."

                else:
                    new_customer_id_response = execute(
                        "CALL new_customer_uid;", 'get', conn)
                    new_customer_id = new_customer_id_response['result'][0]['new_id']

                    execute("""INSERT INTO customers
                            SET customer_uid = \'""" + new_customer_id + """\',
                                customer_created_at = \'""" + ts + """\',
                                customer_email = \'""" + customer_email + """\',
                                customer_first_name = \'""" + customer_first_name + """\',
                                customer_last_name = \'""" + customer_last_name + """\',
                                user_access_token = \'""" + user_access_token + """\',
                                social_id = \'""" + social_id + """\',
                                role = \'""" + role + """\',
                                user_social_media = \'""" + user_social_media + """\',
                                user_refresh_token = \'""" + user_refresh_token + """\',
                                access_expires_in = \'""" + access_expires_in + """\',
                                customer_phone_num = \'""" + customer_phone_num + """\';""", 'post', conn)
                    response['message'] = 'successful'
                    response['result'] = new_customer_id

                return response, 200
            except:
                raise BadRequest('Request failed, please try again later.')
            finally:
                disconnect(conn)
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            timestamp = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
            try:
                data = request.get_json(force=True)
                email_id = data["email_id"]
                first_name = data["first_name"]
                last_name = data["last_name"]
                time_zone = data["time_zone"]
                google_auth_token = data["google_auth_token"]
                social_id = data["social_id"]
                google_refresh_token = data["google_refresh_token"]
                access_expires_in = data["access_expires_in"]

                user_id_response = execute(
                    """SELECT user_unique_id FROM users
                                                WHERE user_email_id = \'"""
                    + email_id
                    + """\';""",
                    "get",
                    conn,
                )

                if len(user_id_response["result"]) > 0:
                    response["message"] = "User already exists"

                else:
                    user_id_response = execute(
                        "CAll get_user_id;", "get", conn)
                    new_user_id = user_id_response["result"][0]["new_id"]

                    execute(
                        """INSERT INTO users
                            SET user_unique_id = \'""" + new_user_id + """\',
                                user_timestamp = \'""" + timestamp + """\',
                                user_email_id = \'""" + email_id + """\',
                                user_first_name = \'""" + first_name + """\',        
                                user_last_name = \'""" + last_name + """\',        
                                social_id = \'""" + social_id + """\',        
                                google_auth_token = \'""" + google_auth_token + """\',        
                                google_refresh_token = \'""" + google_refresh_token + """\',       
                                access_expires_in = \'""" + access_expires_in + """\',        
                                time_zone = \'""" + time_zone + """\',        
                                user_have_pic = \'""" + "False" + """\',        
                                user_picture = \'""" + "" + """\',        
                                user_social_media = \'""" + "null" + """\',        
                                new_account = \'""" + "True" + """\',        
                                user_guid_device_id_notification = \'""" + "null" + """\';""", "post",
                        conn,
                    )

                    response["message"] = "successful"
                    response["result"] = new_user_id

                return response, 200
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
        elif projectName == 'FINDME':
            conn = connect('find_me')

            data = request.get_json(force=True)

            email = data.get('email')
            phoneNumber = data.get('phone_number')
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            role = data.get('role')
            google_auth_token = data.get('google_auth_token')
            google_refresh_token = data.get('google_refresh_token')
            social_id = data.get('social_id')
            access_expires_in = data.get('access_expires_in')
            password = data.get('password')
            user = getUserByEmail(email, projectName)
            email_validated = str(randint(100, 999))
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber, email, password, role, email_validated,
                                  google_auth_token, google_refresh_token, social_id, access_expires_in, 'FINDME')

                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = user
            return response
        elif projectName == 'MMU':
            print("In MMU")
            conn = connect('mmu')

            data = request.get_json(force=True)
            print("MMU Social data: ", data)
            email = data.get('email')
            phoneNumber = data.get('phone_number')
            firstName = "" # data.get('first_name')
            lastName = "" # data.get('last_name')
            role = "" # data.get('role')
            google_auth_token = data.get('google_auth_token')
            google_refresh_token = data.get('google_refresh_token')
            social_id = data.get('social_id')
            access_expires_in = data.get('access_expires_in')
            password = data.get('password')
            user = getUserByEmail(email, projectName)
            email_validated = str(randint(100, 999))
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber, email, password, role, email_validated,
                                  google_auth_token, google_refresh_token, social_id, access_expires_in, 'MMU')

                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = user
            return response

    def put(self, projectName):
        print("In UserSocialSignUp - PUT")
        response = {}
        global encrypt_flag 
        items = {}
        
        if projectName == 'MYSPACE':
            encrypt_flag = True
            data = request.get_json(force=True)

            if not ("user_uid" in data):
                return "ERROR - user_id missing"

            conn = connect('space')            
            userUID = data.get('user_uid')
            email = data.get('email')
            phoneNumber = data.get('phone_number')
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            role = data.get('role')
            google_auth_token = data.get('google_auth_token')
            google_refresh_token = data.get('google_refresh_token')
            social_id = data.get('social_id')
            access_expires_in = data.get('access_expires_in')
            password = data.get('password')

            passwordSalt = createSalt()
            passwordHash = createHash(password, passwordSalt)            

            user = getUserByUID(userUID, projectName)
            if not user:
                response['message'] = 'User does not exist'
                response['code'] = 404
            else:                
                query_update = """
                    UPDATE space.users 
                        SET 
                        first_name = \'""" + firstName + """\',
                        last_name = \'""" + lastName + """\',
                        phone_number = \'""" + phoneNumber + """\',
                        email = \'""" + email + """\',
                        role = \'""" + role + """\',
                        google_auth_token = \'""" + google_auth_token + """\',
                        google_refresh_token =  \'""" + google_refresh_token + """\',
                        social_id = \'""" + social_id + """\',
                        access_expires_in = \'""" + access_expires_in + """\',
                        password_salt = \'""" + passwordSalt + """\',                        
                        password_hash = \'""" + passwordHash + """\'                        
                    WHERE user_uid = \'""" + userUID + """\' """
                                
                newUser = {
                    'user_uid': userUID,
                    'first_name': firstName,
                    'last_name': lastName,
                    'phone_number': phoneNumber,
                    'email': email,
                    'password_salt': passwordSalt,
                    'password_hash': passwordHash,
                    'role': role,
                    'google_auth_token': google_auth_token,
                    'google_refresh_token': google_refresh_token,
                    'social_id': social_id,
                    'access_expires_in': access_expires_in
                }

                items = execute(query_update, "post", conn)                
                response['message'] = 'User details updated'
                response['code'] = 200
                response['result'] = createTokens(newUser, projectName)
            return response
        

# user social login
class UserSocialLogin(Resource):
    def get(self, projectName, email_id):
        print("In UserSocialLogin")
        response = {}
        global encrypt_flag 
        items = {}
        if projectName == 'PM':
            conn = connect('pm')
            user = getUserByEmail(email_id, projectName)
            if user:
                user_unique_id = user.get('user_uid')
                google_auth_token = user.get('google_auth_token')
                response['result'] = user_unique_id, google_auth_token
                response['message'] = 'Correct Email'
            else:
                response['result'] = False
                response['message'] = 'Email ID doesnt exist'
            return response
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            user = getUserByEmail(email_id, projectName)
            if user:
                if user['social_id'] == '':
                    response['message'] = 'Login with email'
                    response['result'] = False

                else:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = createTokens(user, projectName)
            else:
                response['result'] = False
                response['message'] = 'Email ID doesnt exist'
            return response
        elif projectName == 'NITYA':
            conn = connect('nitya')

            user = getUserByEmail(email_id, projectName)
            if user:
                user_unique_id = user.get('customer_uid')
                google_auth_token = user.get('user_access_token')
                response['result'] = user_unique_id, google_auth_token
                response['message'] = 'Correct Email'
            else:
                response['result'] = False
                response['message'] = 'Email ID doesnt exist'
            return response
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            user = getUserByEmail(email_id, projectName)
            if user:
                user_unique_id = user.get('user_unique_uid')
                google_auth_token = user.get('google_auth_token')
                response['result'] = user_unique_id, google_auth_token
                response['message'] = 'Correct Email'
            else:
                response['result'] = False
                response['message'] = 'Email ID doesnt exist'
            return response
        elif projectName == 'FINDME':
            conn = connect('find_me')
            user = getUserByEmail(email_id, projectName)
            if user:
                print(user)
                if user['social_id'] == '':
                    response['message'] = 'Login with email'
                    response['result'] = False

                else:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = user
            else:
                response['result'] = False
                response['message'] = 'Email ID doesnt exist'
            return response
        elif projectName == 'MMU':
            conn = connect('mmu')
            user = getUserByEmail(email_id, projectName)
            if user:
                print(user)
                if user['user_social_id'] == '':
                    response['message'] = 'Login with email'
                    response['result'] = False

                else:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = user
            else:
                response['result'] = False
                response['message'] = 'Email ID doesnt exist'
            return response


# SEND EMAIL
class SendEmail(Resource):

    def post(self):
        print("In Send Email post")
        data = request.get_json(force=True)
        email = data['email']
        code = data['code']
        subject = "Email Verification Code"
        message = "Email Verification Code Sent " + code
        sendEmail(email, subject, message)
        return 'Email Sent'


# -- DEFINE APIS -------------------------------------------------------------------------------
# signup endpoints
api.add_resource(CreateAccount, "/api/v2/CreateAccount/<string:projectName>")
api.add_resource(UpdateUser, "/api/v2/UpdateUser/<string:projectName>")
api.add_resource(UpdateUserByUID, "/api/v2/UpdateUserByUID/<string:projectName>")
# login endpoints
api.add_resource(AccountSalt, "/api/v2/AccountSalt/<string:projectName>")
api.add_resource(Login, "/api/v2/Login/<string:projectName>")
# update password
api.add_resource(SetTempPassword, "/api/v2/SetTempPassword/<string:projectName>")
api.add_resource(UpdateEmailPassword, "/api/v2/UpdateEmailPassword/<string:projectName>")
# token endpoints
api.add_resource(UpdateAccessToken, "/api/v2/UpdateAccessToken/<string:projectName>/<string:user_id>")
api.add_resource(UserToken, "/api/v2/UserToken/<string:projectName>/<string:user_email_id>")
# get info endpoints
api.add_resource(UserDetails, "/api/v2/UserDetails/<string:projectName>/<string:user_id>")
api.add_resource(UserDetailsByEmail, "/api/v2/UserDetailsByEmail/<string:projectName>/<string:email_id>")
api.add_resource(GetEmailId, "/api/v2/GetEmailId/<string:projectName>/<string:email_id>")
api.add_resource(GetUsers, "/api/v2/GetUsers/<string:projectName>")

# social signup and login endpoints
api.add_resource(UserSocialSignUp,
                 "/api/v2/UserSocialSignUp/<string:projectName>")
api.add_resource(UserSocialLogin, "/api/v2/UserSocialLogin/<string:projectName>/<string:email_id>")
api.add_resource(SendEmail, "/api/v2/SendEmail")
api.add_resource(CheckEmailValidationCode, "/api/v2/CheckEmailValidationCode/<string:projectName>")



# @app.route('/decrypt', methods=['POST'])
# def decrypt_data():
#     try:
#         # Get the encrypted data from the request body
#         encrypted_data_base64 = request.json.get('encrypted_data')
#         # print("encrypted_data: ", encrypted_data_base64)
#         decrypted_data = decrypt_dict(encrypted_data_base64)
#         print("Decrypted Data: ", decrypt_data)
        
#         return jsonify({"decrypted_data": decrypted_data})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# Flask runs this code BEFORE running the actual endpoint code
# @app.before_request

# def check_jwt_token():
#     if request.path == '/auth/refreshToken':
#         return
#     try:
#         if request.method == 'OPTIONS':  
#             return '', 200
        
#         print('Request Headers:', request.headers['Authorization'])
#         verify_jwt_in_request()
#         current_user = get_jwt_identity() 
#         print(f"Current User ID: {current_user}")
#     except jwt.ExpiredSignatureError:
#         print('JWT Expired')
#         return jsonify({'message': 'Token is expired!'}), 401

#     except jwt.InvalidTokenError:
#         print('JWT Invalid')
#         return jsonify({'message': 'Invalid token!'}), 401

#     except Exception as e:
#         # This will catch any other exception, including missing token
#         print('JWT Missing')
#         return jsonify({'message': 'Missing token!'}), 401


# Middleware for decrypting incoming request data
# def decrypt_request():
#     print("In decrypt request")
#     if request.is_json:
#         encrypted_data = request.get_json().get('encrypted_data')
#         form_data = request.get_json().get('data_type') # True = Form data, False = JSON data
#         if encrypted_data and form_data == False:
#             print("JSON data received")
#             decrypted_data = decrypt_dict(encrypted_data)
#             request._cached_json = decrypted_data  # Override the request JSON
#         # elif encrypted_data and form_data == True:
#         #     decrypted_data = decrypt_dict(encrypted_data)
#         #     # Convert JSON to Form Data
#         #     form_data = {}
#         #     for key, value in decrypted_data.items():
#         #         if isinstance(value, dict) and 'fileName' in value and 'fileType' in value:
#         #             print("File Received: ", value['fileName'], value['fileType'])
#         #             # Check for 'fileData' field and simulate a file stream
#         #             file_stream = None
#         #             if 'fileData' in value:
#         #                 print("Actual conversion started")
#         #                 file_binary = base64.b64decode(value['fileData'])
#         #                 print("Binary created")
#         #                 file_stream = BytesIO(file_binary)  # Simulated file stream
#         #                 print("File Stream created")
#         #             # If the value represents a file, simulate a FileStorage object
#         #             form_data[key] = FileStorage(
#         #                 stream=file_stream,  # Set to actual stream if available
#         #                 filename=value['fileName'],
#         #                 content_type=value['fileType']
#         #             ) 
#         #         else:
#         #             form_data[key] = value
#         #     print("Form Data: ", form_data)
#         #     request._cached_json = form_data  # Override the request JSON
#             print("Decrypted Request: ", request)
#         else:
#             print("Data issue")
        

#     else:
#         print("no JSON object received")

    

# Middleware to encrypt response data
# def encrypt_response(data):
#     encrypted_data = encrypt_dict(data)
#     return jsonify({'encrypted_data': encrypted_data})


# Health check route (optional)
# @app.route('/')
# def health_check():
#     print("In Health Check")
#     return jsonify({"message": "API is running!"})


# Actual middleware.  Commands before request (check JWT and then decrypt data) and after request (encrypt response before passing to FrontEnd)
# def setup_middlewares(app):
# @app.before_request 
# def before_request():
#     print("In Middleware before_request")
#     # check_jwt_token()
#     decrypt_request()


# @app.after_request
# def after_request(response):
#     print("In Middleware after_request")
#     print("Actual endpoint response: ", type(response))
#     print("Actual endpoint response2: ", type(response.get_json()))
#     response = encrypt_response(response.get_json()) if response.is_json else response
#     return response

# Apply middlewares
# setup_middlewares(app)

#This method is to refresh the jwt token from the FrontEnd
# @app.route('/auth/refreshToken', methods=['POST'])
# @jwt_required(refresh=True)  # This ensures that only refresh tokens can be used here
# def refreshToken():
#     try:
#         print('Inside refresh token')
#         current_user = get_jwt_identity()  # Get user identity from refresh token
#         new_access_token = create_access_token(identity=current_user)  # Create new access token
#         print('New token is', new_access_token)
#         return jsonify(access_token=new_access_token)
#     except Exception as e:
#         print('Error refreshing token:', e)
#         return jsonify({'message': 'Could not refresh token'}), 401




# new middleware

# Middleware for decrypting incoming request data
def decrypt_request():
    if request.is_json:
        encrypted_data = request.get_json().get('encrypted_data')
        form_data = request.get_json().get('data_type') # True = Form data, False = JSON data
        if encrypted_data and form_data == False:
            decrypted_data = decrypt_dict(encrypted_data)
            # print("Decrypted data: ", decrypted_data)
            
            # Override request.get_json() to return decrypted data
            def get_json_override(*args, **kwargs):
                return decrypted_data

            request.get_json = get_json_override
        else:
            print("Data issue")
    elif request.content_type and request.content_type.startswith('multipart/form-data'):
        # For FormData directly in the request
        encrypted_data = request.form.get('encrypted_data')

        if encrypted_data:
            decrypted_data = decrypt_dict(encrypted_data)
            # print("decrypted_data: ", decrypted_data)
            fields = {}
            files = {}

            for key, value in decrypted_data.items():
                if isinstance(value, dict) and 'fileName' in value and 'fileType' in value:
                    # Handle file-specific data
                    # print("image - ", value)
                    file_binary = base64.b64decode(value['fileData'])
                    file_stream = BytesIO(file_binary)
                    files[key] = FileStorage(
                        stream=file_stream,
                        filename=value['fileName'],
                        content_type=value['fileType']
                    )
                else:
                    fields[key] = value

            # Update `request.form` and `request.files`

            # print(" Fields: ", fields)
            request.form = ImmutableMultiDict(fields)
            request.files = ImmutableMultiDict(files)

            # print("Updated Form Data:", request.form)
            # print("Updated Files:", request.files)
        else:
            print("No encrypted data found in multipart/form-data request")
    else:
        print("GET Request, no JSON object received")

# Middleware to encrypt response data
def encrypt_response(data):
    encrypted_data = encrypt_dict(data)
    return jsonify({'encrypted_data': encrypted_data})



# Actual middleware.  Commands before request (check JWT and then decrypt data) and after request (encrypt response before passing to FrontEnd)
# def setup_middlewares(app):
@app.before_request 
def before_request():
    # Extract projectName and apply middleware logic if it matches the condition
    project_name = get_project_name_from_request()
    if project_name == "MYSPACE":
        print("In Middleware before_request for MYSPACE")
        decrypt_request()


@app.after_request
def after_request(response):
    global encrypt_flag 
    print("Encrypt Flag: ", encrypt_flag)
    if encrypt_flag == True:
        print("In Middleware after_request")
        print("Actual endpoint response: ", type(response))
        print("Actual endpoint response2: ", type(response.get_json()))
        original_status_code = response.status_code
        # print(response.get_json()['code'])

        response = encrypt_response(response.get_json()) if response.is_json else response
        
        response.status_code = original_status_code

        encrypt_flag = False

    return response


def get_project_name_from_request():

    #Extract projectName from request
    if request.view_args and "projectName" in request.view_args:
        return request.view_args["projectName"]
    
    return None  # This case occur when projectName is not present in request


if __name__ == "__main__":
    # app.run()
    app.run(host="127.0.0.1", port=2000)
