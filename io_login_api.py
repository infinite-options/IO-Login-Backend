# IO LOGIN (FOR ALL IO PROGRAMS) BACKEND PYTHON FILE
# https://mrle52rri4.execute-api.us-west-1.amazonaws.com/dev/api/v2/<enter_endpoint_details>

# To run program:  python3 io_login_api.py

# README:  if conn error make sure password is set properly in RDS PASSWORD section

# README:  Debug Mode may need to be set to False when deploying live (although it seems to be working through Zappa)

# README:  if there are errors, make sure you have all requirements are loaded
# pip3 install -r requirements.txt

print("-------------------- New Program Run --------------------")


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

from data import connect, disconnect, serializeResponse, execute
from getProfile import getBusinessProfileInfo, getTenantProfileInfo, getOwnerProfileInfo
from encryption import (
    encrypt_dict, decrypt_dict, handle_encrypted_request, create_json_override,
    encrypt_response, handle_before_request, handle_after_request, get_project_name_from_request,
    decrypt_request
)
from auth import createTokens, createSalt, createHash, getHash
from queries import db_lookup, user_lookup_query



# Using cryptograpghy
# AES_KEY = b'IO95120secretkey'  # 16 bytes
# BLOCK_SIZE = 16  # AES block size

load_dotenv()
POSTMAN_SECRET = os.getenv('POSTMAN_SECRET')
# print("POSTMAN_SECRET: ", POSTMAN_SECRET)
full_encryption_projects = ["MYSPACE", "MYSPACE-DEV"]

encrypt_flag = False
project_name = ""




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



def sendEmail(recipient, subject, body):
    with app.app_context():

        msg = Message(
            sender="support@manifestmy.space",
            recipients=[recipient],
            subject=subject,
            body=str(body)
        )
        mail.send(msg)

# def getUserByUID(uid, projectName):
#     global encrypt_flag 
#     if projectName == "MYSPACE-DEV":
#         encrypt_flag = True
#         conn = connect('space_dev')
#         # get user
#         user_lookup_query = ("""
#             SELECT * 
#             FROM space_dev.users
#             WHERE user_uid = \'""" + uid + """\';
#             """)
#         result = execute(user_lookup_query, "get", conn)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     if projectName == "MYSPACE":
#         encrypt_flag = True
#         conn = connect('space_prod')
#         # get user
#         user_lookup_query = ("""
#             SELECT * 
#             FROM space_prod.users
#             WHERE user_uid = \'""" + uid + """\';
#             """)
#         result = execute(user_lookup_query, "get", conn)
#         if len(result['result']) > 0:
#             return result['result'][0]

# def getUserByEmail(email, projectName):
#     print("In getUserByEmail")
#     global encrypt_flag 
#     if projectName == "PM":
#         conn = connect('pm')
#         # get user
#         user_lookup_query = ("""
#         SELECT * FROM pm.users
#         WHERE email = \'""" + email + """\';""")
#         result = execute(user_lookup_query, "get", conn)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     elif projectName == "MYSPACE-DEV":
#         encrypt_flag = True
#         conn = connect('space_dev')
#         # get user
#         user_lookup_query = ("""
#             SELECT * 
#             FROM space_dev.users
#             WHERE email = \'""" + email + """\';
#             """)
#         result = execute(user_lookup_query, "get", conn)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     elif projectName == "MYSPACE":
#         encrypt_flag = True
#         conn = connect('space_prod')
#         # get user
#         user_lookup_query = ("""
#             SELECT * 
#             FROM space_prod.users
#             WHERE email = \'""" + email + """\';
#             """)
#         result = execute(user_lookup_query, "get", conn)
#         print(result)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     elif projectName == "EVERY-CIRCLE":
#         # print("In EveryCircle")
#         encrypt_flag = False
#         conn = connect('every_circle')
#         # get user
#         user_lookup_query = ("""
#             SELECT * 
#             FROM every_circle.users
#             WHERE email = \'""" + email + """\';
#             """)
#         # print(user_lookup_query)
#         result = execute(user_lookup_query, "get", conn)
#         # print(result)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     elif projectName == "NITYA":
#         conn = connect('nitya')
#         # get user
#         user_lookup_query = ("""
#         SELECT * FROM nitya.customers
#         WHERE customer_email =\'""" + email + """\';""")
#         result = execute(user_lookup_query, "get", conn)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     elif projectName == "SKEDUL":
#         conn = connect('skedul')
#         # get user
#         user_lookup_query = ("""
#         SELECT * FROM skedul.users
#         WHERE user_email_id = \'""" + email + """\';""")
#         result = execute(user_lookup_query, "get", conn)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     elif projectName == "FINDME":
#         conn = connect('find_me')
#         # get user
#         user_lookup_query = ("""
#         SELECT * FROM find_me.users
#         WHERE email = \'""" + email + """\';""")
#         result = execute(user_lookup_query, "get", conn)
#         if len(result['result']) > 0:
#             return result['result'][0]
#     elif projectName == "MMU":
#         conn = connect('mmu')
#         # get user
#         user_lookup_query = ("""
#         SELECT * FROM mmu.users
#         WHERE user_email_id = \'""" + email + """\';""")
#         result = execute(user_lookup_query, "get", conn)
#         # print("MMU result: ", result)
#         if len(result['result']) > 0:
#             # print("Before return: ", result['result'][0] )
#             return result['result'][0]

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
    elif projectName == 'MYSPACE-DEV':
        encrypt_flag = True
        conn = connect('space_dev')
        query = ["CALL space_dev.new_user_uid;"]
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
            INSERT INTO space_dev.users SET
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
        # print("MYSPACE Query: ", query)
        response = execute(query, "post", conn)
        # print("MYSPACE response: ", response)
        # print("MYSPACE response code: ", response['code'])
        return (newUser, response['code'])
    elif projectName == 'MYSPACE':
        encrypt_flag = True
        conn = connect('space_prod')
        query = ["CALL space_prod.new_user_uid;"]
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
            INSERT INTO space_prod.users SET
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
        # print("MYSPACE Query: ", query)
        response = execute(query, "post", conn)
        # print("MYSPACE response: ", response)
        # print("MYSPACE response code: ", response['code'])
        return (newUser, response['code'])
    elif projectName == 'EVERY-CIRCLE':
        encrypt_flag = False
        conn = connect('every_circle')
        query = ["CALL every_circle.new_user_uid;"]
        NewIDresponse = execute(query[0], "get", conn)

        newUserID = NewIDresponse["result"][0]["new_id"]
        print("Every Circle userID: ", newUserID)
        passwordSalt = createSalt()
        passwordHash = createHash(password, passwordSalt)
        newUser = {
            'user_uid': newUserID,
            # 'first_name': firstName,
            # 'last_name': lastName,
            # 'phone_number': phoneNumber,
            'email': email,
            'password_salt': passwordSalt,
            'password_hash': passwordHash,
            # 'role': role,
            'google_auth_token': google_auth_token,
            'google_refresh_token': google_refresh_token,
            'social_id': social_id,
            'access_expires_in': access_expires_in
        }
        query = ("""
            INSERT INTO every_circle.users SET
                user_uid = \'""" + newUserID + """\',
                -- first_name = \'""" + firstName + """\',
                -- last_name = \'""" + lastName + """\',
                -- phone_number = \'""" + phoneNumber + """\',
                email = \'""" + email + """\',
                password_salt = \'""" + passwordSalt + """\',
                password_hash = \'""" + passwordHash + """\',
                -- role = \'""" + role + """\',
                google_auth_token = \'""" + google_auth_token + """\',
                google_refresh_token = \'""" + google_refresh_token + """\',
                social_id = \'""" + social_id + """\',
                access_expires_in = \'""" + access_expires_in + """\';
                """)
        # print("EVERYCIRCLE Query: ", query)
        response = execute(query, "post", conn)
        # print("EVERYCIRCLE response: ", response)
        # print("EVERYCIRCLE response code: ", response['code'])
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
        print(passwordHash)
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
        print(newUser)
        query = ("""
            INSERT INTO mmu.users SET
                user_uid = \'""" + newUserID + """\',
                -- user_first_name = \'""" + firstName + """\',
                -- user_last_name = \'""" + lastName + """\',
                -- user_phone_number = \'""" + phoneNumber + """\',
                user_email_id = \'""" + email + """\',
                user_password_salt = \'""" + passwordSalt + """\',
                user_password_hash = \'""" + passwordHash + """\',
                -- user_role = \'""" + role + """\',
                user_google_auth_token = \'""" + google_auth_token + """\',
                user_google_refresh_token = \'""" + google_refresh_token + """\',
                user_social_id = \'""" + social_id + """\',
                user_access_expires_in = \'""" + access_expires_in + """\';
                    """)
        print("MMU Query: ", query)
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
        elif projectName == "MYSPACE-DEV": 
            encrypt_flag = True
            try:

                conn = connect('space_dev')
                query = ("""SELECT * FROM space_dev.users;""")
                items = execute(query, "get", conn)
                response["message"] = "Users from MYSPACE"
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

                conn = connect('space_prod')
                query = ("""SELECT * FROM space_prod.users;""")
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
        elif projectName == "EVERY-CIRCLE":
            print("In Every Circle")
            try:

                conn = connect('every_circle')
                query = ("""SELECT * FROM every_circle.users;""")
                items = execute(query, "get", conn)
                response["message"] = "Users from EVERY-CIRCLE"
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
            # user_lookup_query = ("""
            # SELECT * FROM pm.users
            # WHERE email = \'""" + email + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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

        elif projectName == "MYSPACE-DEV":
            encrypt_flag = True
            conn = connect('space_dev')
            # get user
            # user_lookup_query = ("""
            #     SELECT * 
            #     FROM space_dev.users
            #     WHERE email = \'""" + email + """\';
            #     """)
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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
            UPDATE space_dev.users 
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
            conn = connect('space_prod')
            # get user
            # user_lookup_query = ("""
            #     SELECT * 
            #     FROM space_prod.users
            #     WHERE email = \'""" + email + """\';
            #     """)
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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
            UPDATE space_prod.users 
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
            # user_lookup_query = ("""
            # SELECT * FROM nitya.customers
            # WHERE customer_email =\'""" + email + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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

        elif projectName == "EVERY-CIRCLE":
            conn = connect('every_circle')
            # get user
            # user_lookup_query = ("""
            # SELECT * FROM every_circle.users
            # WHERE user_email_id = \'""" + email + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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
            UPDATE every_circle.users 
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
            
        elif projectName == "SKEDUL":
            conn = connect('skedul')
            # get user
            # user_lookup_query = ("""
            # SELECT * FROM skedul.users
            # WHERE user_email_id = \'""" + email + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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
            # user_lookup_query = ("""
            # SELECT * FROM find_me.users
            # WHERE email = \'""" + email + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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
            # user_lookup_query = ("""
            # SELECT * FROM mmu.users
            # WHERE user_email_id = \'""" + email + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(email, projectName)

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
            # user_lookup_query = ("""
            # SELECT * FROM pm.users
            # WHERE user_uid = \'""" + data['id'] + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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

        elif projectName == "MYSPACE-DEV":
            encrypt_flag = True
            conn = connect('space_dev')
            # get user
            # user_lookup_query = ("""
            #     SELECT * 
            #     FROM space_dev.users
            #     WHERE user_uid = \'""" + data['id'] + """\';
            #     """)
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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
            UPDATE space_dev.users 
                SET 
                password_salt = \'""" + salt + """\',
                password_hash =  \'""" + password + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "MYSPACE":
            encrypt_flag = True
            conn = connect('space_prod')
            # get user
            # user_lookup_query = ("""
            #     SELECT * 
            #     FROM space_prod.users
            #     WHERE user_uid = \'""" + data['id'] + """\';
            #     """)
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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
            UPDATE space_prod.users 
                SET 
                password_salt = \'""" + salt + """\',
                password_hash =  \'""" + password + """\'
            WHERE user_uid = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "NITYA":
            conn = connect('nitya')
            # get user
            # user_lookup_query = ("""
            # SELECT * FROM nitya.customers
            # WHERE customer_uid = \'""" + data['id'] + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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

        elif projectName == "EVERY-CIRCLE":
            conn = connect('every_circle')
            # get user
            # user_lookup_query = ("""
            # SELECT * FROM every_circle.users
            # WHERE user_unique_id = \'""" + data['id'] + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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
            UPDATE every_circle.users 
                SET 
                password_salt = \'""" + salt + """\',
                password_hashed =  \'""" + password + """\'
            WHERE user_unique_id = \'""" + user_uid + """\' """

            items = execute(query_update, "post", conn)
            response['message'] = 'User email and password updated successfully'

        elif projectName == "SKEDUL":
            conn = connect('skedul')
            # get user
            # user_lookup_query = ("""
            # SELECT * FROM skedul.users
            # WHERE user_unique_id = \'""" + data['id'] + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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
            # user_lookup_query = ("""
            # SELECT * FROM find_me.users
            # WHERE user_uid = \'""" + data['id'] + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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
            # user_lookup_query = ("""
            # SELECT * FROM mmu.users
            # WHERE user_uid = \'""" + data['id'] + """\';""")
            # user_lookup = execute(user_lookup_query, "get", conn)
            user_lookup = user_lookup_query(user_uid, projectName)

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
        elif projectName == 'MYSPACE-DEV':
            print("In Myspace Account Salt")
            encrypt_flag = True
            conn = connect('space_dev')
            try:
                query = ("""
                    SELECT * 
                    FROM space_dev.users 
                    WHERE email = \'""" + email + """\';
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
            conn = connect('space_prod')
            try:
                query = ("""
                    SELECT * 
                    FROM space_prod.users 
                    WHERE email = \'""" + email + """\';
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
        elif projectName == 'EVERY-CIRCLE':
            print("In Every-Circle Account Salt")
            encrypt_flag = False
            conn = connect('every_circle')
            try:
                query = ("""
                    SELECT * 
                    FROM every_circle.users 
                    WHERE email = \'""" + email + """\';
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
        
        # elif projectName == 'EVERY-CIRCLE':
        #     print("In Every Circle")
        #     conn = connect('every_circle')
        #     try:
        #         print("In EC Query")
        #         query = ("""
        #         SELECT * FROM every_circle.users WHERE user_email_id= \'""" + email + """\';
        #             """)
        #         print(query)
        #         items = execute(query, "get", conn)
        #         print(items)

        #         if not items["result"]:
        #             print(items["result"])
        #             items["message"] = "Email doesn't exists"
        #             items["code"] = 404
        #             return items
        #         items['result'] = [{
        #             "password_algorithm": "SHA256",
        #             "password_salt": str(datetime.now()),
        #         }]
        #         items["message"] = "SALT sent successfully"
        #         items["code"] = 200
        #         return items
        #     except:
        #         raise BadRequest("Request failed, please try again later.")
        #     finally:
        #         disconnect(conn)
        
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            try:
                query = ("""
                SELECT * FROM skedul.users WHERE user_email_id= \'""" + email + """\';
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
            user = user_lookup_query(email, projectName)
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

        elif projectName == 'MYSPACE-DEV':
            encrypt_flag = True
            user = user_lookup_query(email, projectName)
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
            print("In Login MYSPACE")
            encrypt_flag = True
            user = user_lookup_query(email, projectName)
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

        elif projectName == 'EVERY-CIRCLE':
            print("In Login Every-Circle")
            encrypt_flag = True
            # user = getUserByEmail(email, projectName)
            user = user_lookup_query(email, projectName)
            if user:
                if password == user['password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['user_uid'] = user['user_uid']
                    # response['result'] = createTokens(user, projectName)
                else:
                    response['message'] = 'Incorrect password'
                    response['code'] = 401
            else:
                response['message'] = 'Email not found'
                response['code'] = 404

        elif projectName == 'NITYA':
            conn = connect('nitya')
            user = user_lookup_query(email, projectName)
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
            user = user_lookup_query(email, projectName)
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
            user = user_lookup_query(email, projectName)
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
            user = user_lookup_query(email, projectName)
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
            user = user_lookup_query(email, projectName)
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber,
                                  email, password, role, '', '', '', '', '', 'PM')
                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = createTokens(user, projectName)
            return response
        elif projectName == 'MYSPACE-DEV':
            encrypt_flag = True
            print("In MySpace")
            data = request.get_json()
            firstName = data.get('first_name')
            lastName = data.get('last_name')
            phoneNumber = data.get('phone_number')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role')
            user = user_lookup_query(email, projectName)
            if user:
                print("In Myspace User: ", user)
                print("In Myspace User ID: ", user['user_uid'])
                print("In Myspace User ID: ", user['role'])
                response['message'] = 'User already exists'
                response['user_uid'] = user['user_uid']
                response['user_roles'] = user['role']
            else:
                user = createUser(firstName, lastName, phoneNumber,
                                  email, password, role, '', '', '', '', '', 'MYSPACE-DEV')
                # response['user'] = user[0]
                # print("In MySpace: ", user)
                response['message'] = 'Signup success'
                # print("User 0: ", user[0])
                # print("User 1: ", user[1])
                response['code'] = user[1]
                response['result'] = createTokens(user[0], projectName)
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
            user = user_lookup_query(email, projectName)
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
                # print("In MySpace: ", user)
                response['message'] = 'Signup success'
                # print("User 0: ", user[0])
                # print("User 1: ", user[1])
                response['code'] = user[1]
                response['result'] = createTokens(user[0], projectName)
            return response
        elif projectName == 'EVERY-CIRCLE':
            encrypt_flag = False
            print("In EveryCircle")
            data = request.get_json()
            # firstName = data.get('first_name')
            # lastName = data.get('last_name')
            # phoneNumber = data.get('phone_number')
            email = data.get('email')
            password = data.get('password')
            # role = data.get('role')
            user = user_lookup_query(email, projectName)
            if user:
                print("In EveryCircle User: ", user)
                print("In EveryCircle User ID: ", user['user_uid'])
                # print("In EveryCircle User ID: ", user['role'])
                response['message'] = 'User already exists'
                response['user_uid'] = user['user_uid']
                # response['user_roles'] = user['role']
            else:
                user = createUser('', '', '', email, password, '' , '', '', '', '', '', 'EVERY-CIRCLE')
                # response['user'] = user[0]
                # print("New User In EveryCircle: ", user)
                response['user_uid'] = user[0]['user_uid']
                response['message'] = 'Signup success'
                # print("User : ", user[0])
                # print("User Response Code: ", user[1])
                response['code'] = user[1]
                # response['result'] = createTokens(user[0], projectName)
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
        # elif projectName == 'EVERY-CIRCLE':
        #     print("In Every-Circle")
        #     conn = connect('every_circle')
        #     timestamp = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
        #     try:
        #         data = request.get_json(force=True)
        #         print(data)
        #         # firstName = data.get('first_name')
        #         # lastName = data.get('last_name')
        #         # phoneNumber = data.get('phone_number')
        #         email_id = data["email"]
        #         password = data["password"]
        #         print(email_id, password)

        #         user_id_response = execute(
        #             """
        #                 SELECT user_unique_id FROM users
        #                 WHERE user_email_id = \'""" + email_id+ """\';
        #             """,
        #             "get",
        #             conn,
        #         )
        #         print(user_id_response)

        #         if len(user_id_response["result"]) > 0:
        #             response["message"] = "User already exists"

        #         else:
        #             print("In else")
        #             salt = os.urandom(32)
        #             print(salt, type(salt))

        #             dk = hashlib.pbkdf2_hmac(
        #                 "sha256", password.encode("utf-8"), salt, 100000, dklen=128
        #             )
        #             key = (salt + dk).hex()
        #             print(key)

        #             user_id_response = execute(
        #                 "CAll get_user_id;", "get", conn)
        #             new_user_id = user_id_response["result"][0]["new_id"]
        #             print(new_user_id)

        #             execute(
        #                 """
        #                 INSERT INTO users
        #                 SET user_unique_id = \'""" + new_user_id + """\',
        #                     user_timestamp = \'""" + timestamp + """\',
        #                     user_email_id  = \'""" + email_id + """\',
        #                     password_salt = \'""" + salt + """\',
        #                     password_hashed = \'""" + key + """\';
        #                 """,
        #                 "post",
        #                 conn,
        #             )

        #             print(response)
        #             response["message"] = "successful"
        #             response["result"] = new_user_id

        #         return response, 200
        #     except:
        #         raise BadRequest("Request failed, please try again later.")
        #     finally:
        #         disconnect(conn)
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
                            SET user_unique_id = \'""" + new_user_id + """\',
                                user_timestamp = \'""" + timestamp + """\',
                                user_email_id  = \'""" + email_id + """\',
                                user_first_name = \'""" + first_name + """\',
                                user_last_name = \'""" + last_name + """\',
                                password_hashed = \'""" + key + """\',
                                time_zone = \'""" + time_zone + """\';""",
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
            user = user_lookup_query(email, projectName)
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
            # phoneNumber = data.get('phone_number')
            phoneNumber = data.get('phone_number') if data.get('phone_number') else ""
            email = data.get('email')
            password = data.get('password')
            # role = data.get('role')
            user = user_lookup_query(email, projectName)
            # email_validated = str(randint(100, 999))
            if user:
                response['message'] = 'User already exists'
            else:
                print(firstName, lastName, phoneNumber, email, password, '', '', '', '', '', '', 'MMU')
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
        if projectName == 'MYSPACE-DEV':
            encrypt_flag = True
            conn = connect('space_dev')            
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
                UPDATE space_dev.users 
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
            

        elif projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space_prod')            
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
                UPDATE space_prod.users 
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
            if projectName == 'MYSPACE-DEV':
                encrypt_flag = True
                conn = connect('space_dev')
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
                query = "UPDATE space_dev.users SET " + fields_to_update_str + \
                    " WHERE user_uid = \'" + user_uid + "\';"
                response = execute(query, "post", conn)
            elif projectName == 'MYSPACE':
                encrypt_flag = True
                conn = connect('space_prod')
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
                query = "UPDATE space_prod.users SET " + fields_to_update_str + \
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
        elif projectName == 'MYSPACE-DEV':
            encrypt_flag = True
            conn = connect('space_dev')

            query = """
                UPDATE space_dev.users
                SET google_auth_token = \'""" + google_auth_token + """\'
                WHERE user_uid = \'""" + user_id + """\' """
            response = execute(query, "post", conn)

            return response, 200
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space_prod')

            query = """
                UPDATE space_prod.users
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
        elif projectName == 'EVERY-CIRCLE':
            conn = connect('every_circle')
            query = """UPDATE every_circle.users 
                        SET  google_auth_token = \'""" + google_auth_token + """\'
                        WHERE user_unique_id = \'""" + user_id + """\';
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
        elif projectName == 'MYSPACE-DEV':
            encrypt_flag = True
            conn = connect('space_dev')
            query = ("""
                SELECT user_uid
                    , email
                    , google_auth_token
                    , google_refresh_token
                FROM space_dev.users 
                WHERE email = \'"""+ user_email_id+ """\';
                """
            )
            response = execute(query, 'get', conn)

            return response, 200
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space_prod')
            query = ("""
                SELECT user_uid
                    , email
                    , google_auth_token
                    , google_refresh_token
                FROM space_prod.users 
                WHERE email = \'"""+ user_email_id+ """\';
                """
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
        
        elif projectName == 'EVERY-CIRCLE':
            conn = connect('every_circle')
            query = (
                """SELECT user_unique_id
                                , user_email
                                , google_auth_token
                                , google_refresh_token
                        FROM
                        users WHERE user_email_id= \'"""
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
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            query = (
                """SELECT user_unique_id
                                , user_email
                                , google_auth_token
                                , google_refresh_token
                        FROM
                        users WHERE user_email_id= \'"""
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
        elif projectName == 'MYSPACE-DEV':
            encrypt_flag = True
            conn = connect('space_dev')
            if user_id[0] == '1':
                query = """
                    SELECT user_uid
                    , email
                    , first_name
                    , last_name
                    , google_auth_token
                    , google_refresh_token 
                FROM space_dev.users 
                WHERE user_uid = \'""" + user_id + """\' 
                """

                response = execute(query, 'get', conn)

            elif user_id[0] == '3':
                query = """
                    SELECT user_uid
                    , email
                    , first_name
                    , last_name
                    , google_auth_token
                    , google_refresh_token 
                    FROM space_dev.tenantProfileInfo t
                    LEFT JOIN space_dev.users u ON t.tenant_user_id = u.user_uid 
                    WHERE tenant_id = \'""" + user_id + """\' 
                    """

                response = execute(query, 'get', conn)

            else:
                query = """ 
                    SELECT business_uid
                    , business_email
                    , business_name 
                    FROM space_dev.businessProfileInfo 
                    WHERE business_uid = \'""" + user_id + """\' 
                    """
                business_email = execute(query, 'get', conn)
                query = """
                    SELECT user_uid
                    , email
                    , first_name
                    , last_name
                    , google_auth_token
                    , google_refresh_token 
                    FROM space_dev.users 
                    WHERE email = \'""" + business_email['result'][0]['business_email'] + """\' 
                    """
                response = execute(query, 'get', conn)
            return response
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            conn = connect('space_prod')
            if user_id[0] == '1':
                query = """
                    SELECT user_uid
                    , email
                    , first_name
                    , last_name
                    , google_auth_token
                    , google_refresh_token 
                FROM space_prod.users 
                WHERE user_uid = \'""" + user_id + """\' 
                """

                response = execute(query, 'get', conn)

            elif user_id[0] == '3':
                query = """
                    SELECT user_uid
                    , email
                    , first_name
                    , last_name
                    , google_auth_token
                    , google_refresh_token 
                    FROM space_prod.tenantProfileInfo t
                    LEFT JOIN space_prod.users u ON t.tenant_user_id = u.user_uid 
                    WHERE tenant_id = \'""" + user_id + """\' 
                    """

                response = execute(query, 'get', conn)

            else:
                query = """ 
                    SELECT business_uid
                    , business_email
                    , business_name 
                    FROM space_prod.businessProfileInfo 
                    WHERE business_uid = \'""" + user_id + """\' 
                    """
                business_email = execute(query, 'get', conn)
                query = """
                    SELECT user_uid
                    , email
                    , first_name
                    , last_name
                    , google_auth_token
                    , google_refresh_token 
                    FROM space_prod.users 
                    WHERE email = \'""" + business_email['result'][0]['business_email'] + """\' 
                    """
                response = execute(query, 'get', conn)
            return response
        elif projectName == 'EVERY-CIRCLE':
            conn = connect('every_circle')
            query = None

            query = ("""
                    SELECT user_unique_id
                    , user_email_id
                    , user_first_name
                    , user_last_name
                    , google_auth_token
                    , google_refresh_token
                    FROM users WHERE user_unique_id = \'""" + user_id + """\';
                    """)
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
        elif projectName == 'SKEDUL':
            conn = connect('skedul')
            query = None

            query = ("""
                    SELECT user_unique_id
                    , user_email_id
                    , user_first_name
                    , user_last_name
                    , google_auth_token
                    , google_refresh_token
                    FROM users WHERE user_unique_id = \'""" + user_id + """\';
                    """)
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
        elif projectName == 'EVERY-CIRCLE':
            # print("In Every-Circle ", email_id, type(email_id))
            conn = connect('every_circle')
            try:
                emails = execute(
                    """
                    SELECT user_uid, email
                    FROM every_circle.users
                    -- WHERE email = 'pmtest1@gmail.com'
                    WHERE email = \'""" + email_id + """\';
                    """,
                    "get",
                    conn,
                )
                # print(emails["result"])
                if len(emails["result"]) > 0:
                    response["message"] = "User EmailID exists"
                    response["result"] = emails["result"][0]["user_uid"]
                else:
                    response["message"] = "User EmailID doesnt exist"

                return response, 200
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)
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
            user = user_lookup_query(email, projectName)
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber, email, password, role, '',
                                  google_auth_token, google_refresh_token, social_id, access_expires_in, 'PM')
                response['message'] = 'Signup success'
                response['code'] = 200
                response['result'] = createTokens(user, projectName)
            return response
        elif projectName == 'MYSPACE-DEV':
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
            user = user_lookup_query(email, projectName)
            if user:
                response['message'] = 'User already exists'
            else:
                user = createUser(firstName, lastName, phoneNumber, email, password, role, '',
                                  google_auth_token, google_refresh_token, social_id, access_expires_in, 'MYSPACE-DEV')
                response['message'] = 'Signup success'
                response['code'] = user[1]
                response['result'] = createTokens(user[0], projectName)
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
            user = user_lookup_query(email, projectName)
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
        elif projectName == 'EVERY-CIRCLE':
            conn = connect('every_circle')
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
            user = user_lookup_query(email, projectName)
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
            user = user_lookup_query(email, projectName)
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
        
        if projectName == 'MYSPACE-DEV':
            encrypt_flag = True
            data = request.get_json(force=True)

            if not ("user_uid" in data):
                return "ERROR - user_id missing"

            conn = connect('space_dev')            
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

            # user = getUserByUID(userUID, projectName)
            user = user_lookup_query(userUID, projectName)
            if not user:
                response['message'] = 'User does not exist'
                response['code'] = 404
            else:                
                query_update = """
                    UPDATE space_dev.users 
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
        
        elif projectName == 'MYSPACE':
            encrypt_flag = True
            data = request.get_json(force=True)

            if not ("user_uid" in data):
                return "ERROR - user_id missing"

            conn = connect('space_prod')            
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

            # user = getUserByUID(userUID, projectName)
            user = user_lookup_query(userUID, projectName)
            if not user:
                response['message'] = 'User does not exist'
                response['code'] = 404
            else:                
                query_update = """
                    UPDATE space_prod.users 
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
        items = {}

        # global encrypt_flag 

        # db = db_lookup(projectName)

        # conn = connect(db)
        # print(conn)
        
        user = user_lookup_query(email_id, projectName)

        if user:
            if projectName == 'MYSPACE' or projectName == 'MYSPACE-DEV' :
                if user['social_id'] == '':
                    response['message'] = 'Login with email'
                    response['result'] = False

                else:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = createTokens(user, projectName) 
            else:
                user_unique_id = user.get('user_uid')
                google_auth_token = user.get('google_auth_token')
                response['result'] = user_unique_id, google_auth_token
                response['message'] = 'Correct Email'

        else:
            response['result'] = False
            response['message'] = 'Email ID does not exist'
        return response



        # if projectName == 'PM':
        #     conn = connect('pm')
        #     user = user_lookup_query(email_id, projectName)
        #     if user:
        #         user_unique_id = user.get('user_uid')
        #         google_auth_token = user.get('google_auth_token')
        #         response['result'] = user_unique_id, google_auth_token
        #         response['message'] = 'Correct Email'
        #     else:
        #         response['result'] = False
        #         response['message'] = 'Email ID doesnt exist'
        #     return response
        # elif projectName == 'MYSPACE' or projectName == 'MYSPACE-DEV' :
        #     encrypt_flag = True
        #     user = user_lookup_query(email_id, projectName)
        #     if user:
        #         if user['social_id'] == '':
        #             response['message'] = 'Login with email'
        #             response['result'] = False

        #         else:
        #             response['message'] = 'Login successful'
        #             response['code'] = 200
        #             response['result'] = createTokens(user, projectName)
        #     else:
        #         response['result'] = False
        #         response['message'] = 'Email ID doesnt exist'
        #     return response
        # elif projectName == 'NITYA':
        #     conn = connect('nitya')

        #     user = user_lookup_query(email_id, projectName)
        #     if user:
        #         user_unique_id = user.get('customer_uid')
        #         google_auth_token = user.get('user_access_token')
        #         response['result'] = user_unique_id, google_auth_token
        #         response['message'] = 'Correct Email'
        #     else:
        #         response['result'] = False
        #         response['message'] = 'Email ID doesnt exist'
        #     return response
        # elif projectName == 'EVERY-CIRCLE':
        #     conn = connect('every_circle')
        #     user = user_lookup_query(email_id, projectName)
        #     if user:
        #         user_unique_id = user.get('user_unique_uid')
        #         google_auth_token = user.get('google_auth_token')
        #         response['result'] = user_unique_id, google_auth_token
        #         response['message'] = 'Correct Email'
        #     else:
        #         response['result'] = False
        #         response['message'] = 'Email ID doesnt exist'
        #     return response
        # elif projectName == 'SKEDUL':
        #     conn = connect('skedul')
        #     user = user_lookup_query(email_id, projectName)
        #     if user:
        #         user_unique_id = user.get('user_unique_uid')
        #         google_auth_token = user.get('google_auth_token')
        #         response['result'] = user_unique_id, google_auth_token
        #         response['message'] = 'Correct Email'
        #     else:
        #         response['result'] = False
        #         response['message'] = 'Email ID doesnt exist'
        #     return response
        # elif projectName == 'FINDME':
        #     conn = connect('find_me')
        #     user = user_lookup_query(email_id, projectName)
        #     if user:
        #         print(user)
        #         if user['social_id'] == '':
        #             response['message'] = 'Login with email'
        #             response['result'] = False

        #         else:
        #             response['message'] = 'Login successful'
        #             response['code'] = 200
        #             response['result'] = user
        #     else:
        #         response['result'] = False
        #         response['message'] = 'Email ID doesnt exist'
        #     return response
        # elif projectName == 'MMU':
        #     conn = connect('mmu')
        #     user = user_lookup_query(email_id, projectName)
        #     if user:
        #         print(user)
        #         if user['user_social_id'] == '':
        #             response['message'] = 'Login with email'
        #             response['result'] = False

        #         else:
        #             response['message'] = 'Login successful'
        #             response['code'] = 200
        #             response['result'] = user
        #     else:
        #         response['result'] = False
        #         response['message'] = 'Email ID doesnt exist'
        #     return response


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





# Middleware for decrypting incoming request data
@app.before_request 
def before_request():
    global encrypt_flag
    global project_name
    project_name = get_project_name_from_request()
    # print("Postman Secret: ", request.headers.get("Postman-Secret"))
    encrypt_flag = handle_before_request(project_name, full_encryption_projects, POSTMAN_SECRET)

@app.after_request
def after_request(response):
    global encrypt_flag 
    global project_name
    print("Encrypt Flag: ", encrypt_flag)
    
    response = handle_after_request(response, project_name, full_encryption_projects, POSTMAN_SECRET, encrypt_flag)
    encrypt_flag = False
    return response


if __name__ == "__main__":
    # app.run()
    app.run(host="127.0.0.1", port=2000)
