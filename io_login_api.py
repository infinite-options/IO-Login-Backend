# IO LOGIN (FOR ALL IO PROGRAMS) BACKEND PYTHON FILE
# https://mrle52rri4.execute-api.us-west-1.amazonaws.com/dev/api/v2/<enter_endpoint_details>

# To run program:  python3 io_login_api.py

# README:  if conn error make sure password is set properly in RDS PASSWORD section

# README:  Debug Mode may need to be set to False when deploying live (although it seems to be working through Zappa)

# README:  if there are errors, make sure you have all requirements are loaded
# pip3 install -r requirements.txt


# -- BASIC LOGIN FLOW -------------------------------------------------------------------------------
# EMAIL LOGIN
# 1.  Check individual Project user table to see if User already exists
# 2.  If not, call CreateAccount.  Note: CreateAccount only affects the users table.  Profile tables are updated directly from the individual projects

# SOCIAL LOGIN


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


# Get the correct users for a project
class GetUsers(Resource):
    def get(self, projectName):
        print("In GetUsers ", projectName)
        response = {}
        items = {}

        db = db_lookup(projectName)

        try:
            conn = connect(db)
            print(conn)
            query = (f"""SELECT * FROM {db}.users;""")
            print(query)
            items = execute(query, "get", conn)
            response["message"] = "Users from PM"
            response["result"] = items["result"]

        except:
            raise BadRequest(
                "Request failed, please try again later."
            )
        finally:
            disconnect(conn)

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
                response['message'] = 'User email does not exist'

            return response, 200
        elif projectName == 'EVERY-CIRCLE':
            print("In Every-Circle ", email_id, type(email_id))
            conn = connect('every_circle')
            try:
                emails = execute(
                    """
                    SELECT user_uid, user_email_id
                    FROM every_circle.users
                    -- WHERE user_email_id = 'pmtest1@gmail.com'
                    WHERE user_email_id = \'""" + email_id + """\';
                    """,
                    "get",
                    conn,
                )
                # print(emails["result"])
                if len(emails["result"]) > 0:
                    response["message"] = "User EmailID exists"
                    response["result"] = emails["result"][0]["user_uid"]
                else:
                    response["message"] = "User email does not exist"

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
                    response["message"] = "User email does not exist"

                return response, 200
            except:
                raise BadRequest("Request failed, please try again later.")
            finally:
                disconnect(conn)



class SetTempPassword(Resource):
    def get_random_string(self, stringLength=8):
        lettersAndDigits = string.ascii_letters + string.digits
        return "".join([random.choice(lettersAndDigits) for i in range(stringLength)])

    def post(self, projectName):
        response = {}
         
        items = {}
        user = {}
        data = request.get_json(force=True)
        email = data['email']

        db = db_lookup(projectName)
        conn = connect(db)
        user = user_lookup_query(email, db)
        print("\nBack in Temp Password POST: ", db, user)

        if not user:
                print("In not user")
                response["message"] = "User email does not exist"
                response["code"] = 404
                return response
        
        user_uid = user['user_uid']
        print(user_uid)
        # create password salt and hash
        pass_temp = self.get_random_string()
        passwordSalt = createSalt()
        passwordHash = createHash(pass_temp, passwordSalt)

        # update table
        query_update = f"""
            UPDATE {db}.users 
            SET password_salt = \'""" + passwordSalt + """\',
                password_hash =  \'""" + passwordHash + """\'
            WHERE user_uid = \'""" + user_uid + """\' 
            """
        
        print(query_update)

        items = execute(query_update, "post", conn)
        # send email
        subject = "Email Verification"
        recipient = email
        body = (
            "Your temporary password is {}. Please use it to reset your password".format(pass_temp)
            )
        sendEmail(recipient, subject, body)
        response['message'] = "A temporary password has been sent"

        return response


class UpdateEmailPassword(Resource):
    def post(self, projectName):
        print("In UpdateEmailPassword")
        response = {}
        
        data = request.get_json(force=True)
        user_uid = data['user_uid']

        db = db_lookup(projectName)
        conn = connect(db)
        user = user_lookup_query(user_uid, db)
        print("\nBack in UpdateEmailPassword POST: ", db, user)

        if not user:
                print("In not user")
                response["message"] = "User email does not exist"
                response["code"] = 404
                return response
        
        user_uid = user['user_uid']
        # create password salt and hash
        salt = createSalt()
        password = createHash(data['password'], salt)
        # update table
        query_update = f"""
            UPDATE {db}.users 
                SET 
                password_salt = \'""" + salt + """\',
                password_hash =  \'""" + password + """\'
            WHERE user_uid = \'""" + user_uid + """\' 
            """

        items = execute(query_update, "post", conn)
        print(items)
        # PM Todo: Need conditional statement to confirm successful update
        response['message'] = 'User email and password updated successfully'

        return response


class AccountSalt(Resource):
    def post(self, projectName):
        print("\nIn Account Salt POST")
        response = {}
        items = {}

        data = request.get_json(force=True)
        if "encrypted_data" in data:
            encrypted_data = data["encrypted_data"]
            data = decrypt_dict(encrypted_data)

        print("data: ", data)
        email = data["email"]

        db = db_lookup(projectName)
        conn = connect(db)
        user = user_lookup_query(email, db)
        print("\nBack in Account Salt POST: ", db, user)

        if not user:
                print("In not user")
                response["message"] = "User email does not exist"
                response["code"] = 404
                return response
        
        user_uid = user['user_uid']
        print(user_uid)

        if projectName in ['MMU', 'EVERY-CIRCLE', 'SIGNUP']:
            response['result'] = [{
                        "password_algorithm": "SHA256",
                        "password_salt": user['user_password_salt'],
                    }]
        else:
            response['result'] = [{
                    "password_algorithm": "SHA256",
                    "password_salt": user['password_salt'],
                    }]
        response["message"] = "SALT sent successfully"
        response["code"] = 200
        return response


class Login(Resource):
    def post(self, projectName):
        print("\nIn Login POST ", projectName)
        response = {}
        user = {}

        data = request.get_json(force=True)
        if "encrypted_data" in data:
            encrypted_data = data["encrypted_data"]
            data = decrypt_dict(encrypted_data)

        email = data["email"]
        password = data["password"]
        # password = data.get("password")
        print(email, password)

        db = db_lookup(projectName)
        conn = connect(db)
        user = user_lookup_query(email, db)
        print("\nBack in Login POST: ", db, user)

        if not user:
                print("In not user")
                response["message"] = "User email does not exist"
                response["code"] = 404
                return response
        
        user_uid = user['user_uid']
        print(user_uid)

        if projectName in ['MMU', 'EVERY-CIRCLE', 'SIGNUP']:
            if password == user['user_password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = user
            else:
                response['message'] = 'Incorrect password'
                response['code'] = 401
        elif projectName in ['MYSPACE-DEV', 'MYSPACE']:
            if password == user['password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = createTokens(user, db)
            else:
                response['message'] = 'Incorrect password'
                response['code'] = 401
        else:
            if password == user['password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = user
            else:
                response['message'] = 'Incorrect password'
                response['code'] = 401
        return response

# user social login
class UserSocialLogin(Resource):
    def get(self, projectName, email_id):
        print("In UserSocialLogin ", projectName, email_id)
        response = {}
        
        db = db_lookup(projectName)
        conn = connect(db)
        
        user = user_lookup_query(email_id, db)
        print("\nBack in UserSocialLogin GET: ", db, user)

        if user:
            if projectName == 'MYSPACE' or projectName == 'MYSPACE-DEV' :
                if user['social_id'] == '':
                    response['message'] = 'Login with email'
                    response['result'] = False

                else:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = createTokens(user, db) 
                # response['message'] = 'Login successful'
                # response['code'] = 200
                # response['result'] = createTokens(user, db) 
            elif projectName == 'SKEDUL':
                user_unique_id = user.get('user_uid')
                google_auth_token = user.get('google_auth_token')
                response['result'] = user_unique_id, google_auth_token
                response['message'] = 'Correct Email'
            
            else:
                user_unique_id = user.get('user_uid')
                google_auth_token = user.get('user_google_auth_token')
                response['result'] = user_unique_id, google_auth_token
                response['message'] = 'Correct Email'

        else:
            response['result'] = False
            response['message'] = 'User email does not exist'
        return response


# CreateAccount is identical to UserSocialSignUp
class CreateAccount(Resource):
    def post(self, projectName):
        print("In CreateAccount POST ", projectName)
        response = {}

        db = db_lookup(projectName)
        conn = connect(db)
                
        data = request.get_json(force=True)
        print("Input Data: ", data)

        email = data.get('email', None)
        phone = data.get('phone_number', None)
        firstName = data.get('first_name', None)
        lastName = data.get('last_name', None)
        role = data.get('role', None)
        google_auth_token = data.get('google_auth_token')
        google_refresh_token = data.get('google_refresh_token')
        social_id = data.get('social_id')
        access_expires_in = data.get('access_expires_in')
        password = data.get('password')

        user = user_lookup_query(email, db)    
        print("\nBack in CreateAcount POST: ", db, user)

        if user:
            response['message'] = 'User already exists'
            response['user_uid'] = user['user_uid']
            return response
        
        else:
            user_id_response = execute("CAll new_user_uid;", "get", conn)
            newUserID = user_id_response["result"][0]["new_id"]
            print("newUserID: ", newUserID)

            passwordSalt = createSalt()
            passwordHash = createHash(password, passwordSalt)

            if projectName in ('PM','MYSPACE','MYSPACE-DEV') :  
                query = f"""
                    INSERT INTO {db}.users 
                    SET
                        user_uid = '{newUserID}',
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        email = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        password_salt = '{passwordSalt}',
                        password_hash = '{passwordHash}',
                        created_date = DATE_FORMAT(NOW(), '%m-%d-%Y %H:%i'),
                        google_auth_token = '{google_auth_token}',
                        google_refresh_token = '{google_refresh_token}',
                        social_id = '{social_id}',
                        access_expires_in = '{access_expires_in}';
                        """    
                print(query)
                response = execute(query, "post", conn)
                # print(response)

                query = f"""
                    SELECT * 
                    FROM {db}.users
                    WHERE user_uid = '{newUserID}';
                    """
                print(query)
                user = execute(query, "get", conn)['result'][0]
                print(user)
   
                response['result'] = createTokens(user, db)
                response['message'] = 'Signup success'
                response['code'] = 200

            elif projectName in ['MMU', 'EVERY-CIRCLE', 'SIGNUP'] : 
                query = f"""
                    INSERT INTO {db}.users 
                    SET
                        user_uid = '{newUserID}',
                        user_first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        user_last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        user_phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        user_role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_created_date = DATE_FORMAT(NOW(), '%m-%d-%Y %H:%i'),
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}';
                        """
                print(query)
                response = execute(query, "post", conn)
                response["user_uid"] = newUserID
                print(response)

            else:
                query = f"""
                    INSERT INTO {db}.users 
                    SET
                        user_uid = '{newUserID}',
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_created_date = DATE_FORMAT(NOW(), '%m-%d-%Y %H:%i'),
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}';
                        """
                print(query)
                response = execute(query, "post", conn)
                print(response)

        response['user_uid'] = newUserID
        return response


    def put(self, projectName):
        print(" In CreateAccount - PUT ", projectName)
        response = {}

        db = db_lookup(projectName)
        conn = connect(db)
                
        data = request.get_json(force=True)
        print("Input Data: ", data)

        if not ("user_uid" in data):
            return "ERROR - user_id missing"

        userUID = data.get('user_uid')
        email = data.get('email', None)
        phone = data.get('phone_number', None)
        firstName = data.get('first_name', None)
        lastName = data.get('last_name', None)
        role = data.get('role', None)
        google_auth_token = data.get('google_auth_token')
        google_refresh_token = data.get('google_refresh_token')
        social_id = data.get('social_id')
        access_expires_in = data.get('access_expires_in')
        password = data.get('password')

        user = user_lookup_query(userUID, db)
        print("\nBack in CreateAccount PUT: ", db, user)
        
        if not user:
            response['message'] = 'User does not exist'
            response['code'] = 404

        else: 
            passwordSalt = createSalt()
            passwordHash = createHash(password, passwordSalt)   

            if projectName in ('PM','MYSPACE','MYSPACE-DEV') :  
                print(projectName)
                query = f"""
                    UPDATE {db}.users 
                    SET
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        email = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        password_salt = '{passwordSalt}',
                        password_hash = '{passwordHash}',
                        google_auth_token = '{google_auth_token}',
                        google_refresh_token = '{google_refresh_token}',
                        social_id = '{social_id}',
                        access_expires_in = '{access_expires_in}'
                    WHERE user_uid = '{userUID}';
                    """
                print(query)
                response = execute(query, "post", conn)
                print(response)
   
                response['result'] = createTokens(user, db)
                response['message'] = 'User details updated'
                response['code'] = 200

            elif projectName in ['MMU', 'EVERY-CIRCLE', 'SIGNUP'] : 
                print(projectName)
                query = f"""
                    UPDATE {db}.users 
                    SET
                        user_first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        user_last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        user_phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        user_role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}'
                    WHERE user_uid = '{userUID}';
                    """
                print(query)
                response = execute(query, "post", conn)
                print(response)

            else:
                print(projectName)
                query = f"""
                    UPDATE {db}.users 
                    SET
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}'
                    WHERE user_uid = '{userUID}';
                    """
                print(query)
                response = execute(query, "post", conn)
                print(response)

        response['user_uid'] = userUID
        return response

# creating new user social
class UserSocialSignUp(Resource):
    def post(self, projectName):
        print("In UserSocialSignUp - POST ", projectName)
        response = {}

        db = db_lookup(projectName)
        conn = connect(db)
                
        data = request.get_json(force=True)
        print("Input Data: ", data)

        email = data.get('email', None)
        phone = data.get('phone_number', None)
        firstName = data.get('first_name', None)
        lastName = data.get('last_name', None)
        role = data.get('role', None)
        google_auth_token = data.get('google_auth_token')
        google_refresh_token = data.get('google_refresh_token')
        social_id = data.get('social_id')
        access_expires_in = data.get('access_expires_in')
        password = data.get('password')

        user = user_lookup_query(email, db)
        print("\nBack in UserSocialSignUp POST: ", db, user)   

        if user:
            response['message'] = 'User already exists'
            response['user_uid'] = user['user_uid']
            return response
        
        else:
            user_id_response = execute("CAll new_user_uid;", "get", conn)
            newUserID = user_id_response["result"][0]["new_id"]
            print("newUserID: ", newUserID)

            passwordSalt = createSalt()
            passwordHash = createHash(password, passwordSalt)

            if projectName in ('PM','MYSPACE','MYSPACE-DEV') :  
                print(projectName)
                query = f"""
                    INSERT INTO {db}.users 
                    SET
                        user_uid = '{newUserID}',
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        email = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        password_salt = '{passwordSalt}',
                        password_hash = '{passwordHash}',
                        created_date = DATE_FORMAT(NOW(), '%m-%d-%Y %H:%i'),
                        google_auth_token = '{google_auth_token}',
                        google_refresh_token = '{google_refresh_token}',
                        social_id = '{social_id}',
                        access_expires_in = '{access_expires_in}';
                        """
                print(query)
                response = execute(query, "post", conn)
                print(response)

                query = f"""
                    SELECT * 
                    FROM {db}.users
                    WHERE user_uid = '{newUserID}';
                    """
                print(query)
                user = execute(query, "get", conn)['result'][0]
                print(user)
   
                response['result'] = createTokens(user, db)
                response['message'] = 'Signup success'
                response['code'] = 200

            elif projectName in ['MMU', 'EVERY-CIRCLE', 'SIGNUP'] : 
                print(projectName)
                query = f"""
                    INSERT INTO {db}.users 
                    SET
                        user_uid = '{newUserID}',
                        user_first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        user_last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        user_phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        user_role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_created_date = DATE_FORMAT(NOW(), '%m-%d-%Y %H:%i'),
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}';
                        """
                print(query)
                response = execute(query, "post", conn)
                print(response)

            else:
                query = f"""
                    INSERT INTO {db}.users 
                    SET
                        user_uid = '{newUserID}',
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_created_date = DATE_FORMAT(NOW(), '%m-%d-%Y %H:%i'),
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}';
                        """
                print(query)
                response = execute(query, "post", conn)
                print(response)

        response['user_uid'] = newUserID
        return response

      

    def put(self, projectName):
        print("In UserSocialSignUp - PUT ", projectName)
        response = {}

        db = db_lookup(projectName)
        conn = connect(db)
                
        data = request.get_json(force=True)
        print("Input Data: ", data)

        if not ("user_uid" in data):
            return "ERROR - user_id missing"

        userUID = data.get('user_uid')
        email = data.get('email', None)
        phone = data.get('phone_number', None)
        firstName = data.get('first_name', None)
        lastName = data.get('last_name', None)
        role = data.get('role', None)
        google_auth_token = data.get('google_auth_token')
        google_refresh_token = data.get('google_refresh_token')
        social_id = data.get('social_id')
        access_expires_in = data.get('access_expires_in')
        password = data.get('password')

        user = user_lookup_query(userUID, db)
        print("\nBack in UserSocialSignUp PUT: ", db, user)   
        
        if not user:
            response['message'] = 'User does not exist'
            response['code'] = 404

        else: 
            passwordSalt = createSalt()
            passwordHash = createHash(password, passwordSalt)   

            if projectName in ('PM','MYSPACE','MYSPACE-DEV') :  
                print(projectName)
                query = f"""
                    UPDATE {db}.users 
                    SET
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        email = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        password_salt = '{passwordSalt}',
                        password_hash = '{passwordHash}',
                        google_auth_token = '{google_auth_token}',
                        google_refresh_token = '{google_refresh_token}',
                        social_id = '{social_id}',
                        access_expires_in = '{access_expires_in}'
                    WHERE user_uid = '{userUID}';
                    """
                print(query)
                response = execute(query, "post", conn)
                print(response)
   
                response['result'] = createTokens(user, db)
                response['message'] = 'User details updated'
                response['code'] = 200

            elif projectName in ['MMU', 'EVERY-CIRCLE', 'SIGNUP'] : 
                print(projectName)
                query = f"""
                    UPDATE {db}.users 
                    SET
                        user_first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        user_last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        user_phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        user_role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}'
                    WHERE user_uid = '{userUID}';
                    """
                print(query)
                response = execute(query, "post", conn)
                print(response)

            else:
                print(projectName)
                query = f"""
                    UPDATE {db}.users 
                    SET
                        first_name = {f"'{firstName}'" if firstName is not None else 'NULL'},
                        last_name = {f"'{lastName}'" if lastName is not None else 'NULL'},
                        phone_number = {f"'{phone}'" if phone is not None else 'NULL'},
                        user_email_id = {f"'{email}'" if email is not None else 'NULL'},
                        role = {f"'{role}'" if role is not None else 'NULL'},
                        user_password_salt = '{passwordSalt}',
                        user_password_hash = '{passwordHash}',
                        user_google_auth_token = '{google_auth_token}',
                        user_google_refresh_token = '{google_refresh_token}',
                        user_social_id = '{social_id}',
                        user_access_expires_in = '{access_expires_in}'
                    WHERE user_uid = '{userUID}';
                    """
                print(query)
                response = execute(query, "post", conn)
                print(response)

        response['user_uid'] = userUID
        return response


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
        
        try:
            if projectName == 'MYSPACE-DEV':
                
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
    def post(self, projectName, user_id):
        print("In UpdateAccessToken ", projectName, user_id )
        response = {}

        db = db_lookup(projectName)
        conn = connect(db)
        
        data = request.get_json(force=True)
        print("Input Data: ", data)

        google_auth_token = data["google_auth_token"]

        query = f"""
                UPDATE {db}.users 
                SET
                    google_auth_token = '{google_auth_token}'
                WHERE user_uid = '{user_id}';
                """
        print(query)

        response = execute(query, "post", conn)
        print(response)
        
        return response, 200

        # items = {}
        # data = request.get_json(force=True)
        # google_auth_token = data["google_auth_token"]
        # if projectName == 'PM':
        #     conn = connect('pm')

        #     query = """UPDATE pm.users
        #         SET google_auth_token = \'""" + google_auth_token + """\'
        #         WHERE user_uid = \'""" + user_id + """\' """
        #     response = execute(query, "post", conn)

        #     return response, 200
        # elif projectName == 'MYSPACE-DEV':
            
        #     conn = connect('space_dev')

        #     query = """
        #         UPDATE space_dev.users
        #         SET google_auth_token = \'""" + google_auth_token + """\'
        #         WHERE user_uid = \'""" + user_id + """\' """
        #     response = execute(query, "post", conn)

        #     return response, 200
        # elif projectName == 'MYSPACE':
            
        #     conn = connect('space_prod')

        #     query = """
        #         UPDATE space_prod.users
        #         SET google_auth_token = \'""" + google_auth_token + """\'
        #         WHERE user_uid = \'""" + user_id + """\' """
        #     response = execute(query, "post", conn)

        #     return response, 200
        
        # elif projectName == 'NITYA':
        #     conn = connect('nitya')
        #     query = """UPDATE nitya.customers
        #                SET user_access_token = \'""" + google_auth_token + """\'
        #                WHERE customer_uid = \'""" + user_id + """\';
        #                 """
        #     response = execute(query, "post", conn)
        #     return response, 200
        # elif projectName == 'EVERY-CIRCLE':
        #     conn = connect('every_circle')
        #     query = """UPDATE every_circle.users 
        #                 SET  google_auth_token = \'""" + google_auth_token + """\'
        #                 WHERE user_unique_id = \'""" + user_id + """\';
        #                 """
        #     response = execute(query, "post", conn)
        #     return response, 200
        # elif projectName == 'SKEDUL':
        #     conn = connect('skedul')
        #     query = """UPDATE skedul.users 
        #                 SET  google_auth_token = \'""" + google_auth_token + """\'
        #                 WHERE user_unique_id = \'""" + user_id + """\';
        #                 """
        #     response = execute(query, "post", conn)
        #     return response, 200
        # elif projectName == 'FINDME':
        #     conn = connect('find_me')
        #     query = """UPDATE find_me.users
        #         SET google_auth_token = \'""" + google_auth_token + """\'
        #         WHERE user_uid = \'""" + user_id + """\' """
        #     response = execute(query, "post", conn)
        #     return response


# get user tokens
class UserToken(Resource):
    def get(self, projectName, user_email_id):
        print("In usertoken ",  projectName, user_email_id)
        response = {}
        
        db = db_lookup(projectName)
        conn = connect(db)
        
        data = request.get_json(force=True)
        print("Input Data: ", data)

        query = f"""
                SELECT user_uid
                        , email
                        , google_auth_token
                        , google_refresh_token
                FROM {db}.users 
                WHERE email = '{user_email_id}';
                """
        print(query)

        response = execute(query, 'get', conn)
        print(response)

        return response, 200



    # def get(self, projectName, user_email_id):
    #     print("In usertoken")
    #     response = {}
   
    #     items = {}
    #     if projectName == 'PM':
    #         conn = connect('pm')
    #         query = (
    #             """SELECT user_uid
    #                             , email
    #                             , google_auth_token
    #                             , google_refresh_token
    #                     FROM
    #                     users WHERE email = \'"""
    #             + user_email_id
    #             + """\';"""
    #         )
    #         response = execute(query, 'get', conn)

    #         return response, 200
    #     elif projectName == 'MYSPACE-DEV':
         
    #         conn = connect('space_dev')
    #         query = ("""
    #             SELECT user_uid
    #                 , email
    #                 , google_auth_token
    #                 , google_refresh_token
    #             FROM space_dev.users 
    #             WHERE email = \'"""+ user_email_id+ """\';
    #             """
    #         )
    #         response = execute(query, 'get', conn)

    #         return response, 200
    #     elif projectName == 'MYSPACE':
       
    #         conn = connect('space_prod')
    #         query = ("""
    #             SELECT user_uid
    #                 , email
    #                 , google_auth_token
    #                 , google_refresh_token
    #             FROM space_prod.users 
    #             WHERE email = \'"""+ user_email_id+ """\';
    #             """
    #         )
    #         response = execute(query, 'get', conn)

    #         return response, 200
        
    #     elif projectName == 'NITYA':
    #         conn = connect('nitya')
    #         query = (
    #             """SELECT customer_uid
    #                             , customer_email
    #                             , user_access_token
    #                             , user_refresh_token
    #                     FROM
    #                     customers WHERE customer_email = \'"""
    #             + user_email_id
    #             + """\';"""
    #         )
    #         response = execute(query, 'get', conn)
    #         response["message"] = "successful"
    #         response["customer_uid"] = items["result"][0]["customer_uid"]
    #         response["customer_email"] = items["result"][0]["customer_email"]
    #         response["user_access_token"] = items["result"][0]["user_access_token"]
    #         response["user_refresh_token"] = items["result"][0][
    #             "user_refresh_token"
    #         ]

    #         return response, 200
        
    #     elif projectName == 'EVERY-CIRCLE':
    #         conn = connect('every_circle')
    #         query = (
    #             """SELECT user_unique_id
    #                             , user_email
    #                             , google_auth_token
    #                             , google_refresh_token
    #                     FROM
    #                     users WHERE user_email_id= \'"""
    #             + user_email_id
    #             + """\';"""
    #         )

    #         response = execute(query, 'get', conn)
    #         response["message"] = "successful"
    #         response["user_unique_id"] = items["result"][0]["user_unique_id"]
    #         response["user_email_id"] = items["result"][0]["user_email_id"]
    #         response["google_auth_token"] = items["result"][0]["google_auth_token"]
    #         response["google_refresh_token"] = items["result"][0][
    #             "google_refresh_token"
    #         ]

    #         return response, 200
    #     elif projectName == 'SKEDUL':
    #         conn = connect('skedul')
    #         query = (
    #             """SELECT user_unique_id
    #                             , user_email
    #                             , google_auth_token
    #                             , google_refresh_token
    #                     FROM
    #                     users WHERE user_email_id= \'"""
    #             + user_email_id
    #             + """\';"""
    #         )

    #         response = execute(query, 'get', conn)
    #         response["message"] = "successful"
    #         response["user_unique_id"] = items["result"][0]["user_unique_id"]
    #         response["user_email_id"] = items["result"][0]["user_email_id"]
    #         response["google_auth_token"] = items["result"][0]["google_auth_token"]
    #         response["google_refresh_token"] = items["result"][0][
    #             "google_refresh_token"
    #         ]

    #         return response, 200
    #     elif projectName == 'FINDME':
    #         conn = connect('find_me')
    #         query = (
    #             """SELECT user_uid
    #                             , email
    #                             , google_auth_token
    #                             , google_refresh_token
    #                     FROM
    #                     users WHERE email = \'"""
    #             + user_email_id
    #             + """\';"""
    #         )
    #         response = execute(query, 'get', conn)

    #         return response, 200
    #     elif projectName == 'SF':
    #         conn = connect('sf')
    #         query = (
    #             """SELECT customer_uid
    #                             , customer_email
    #                             , user_access_token
    #                             , user_refresh_token
    #                             , social_id
    #                     FROM
    #                     sf.customers WHERE customer_email = \'"""
    #             + user_email_id
    #             + """\';"""
    #         )
    #         response = execute(query, 'get', conn)

    #         return response, 200


class UserDetails(Resource):
    def get(self, projectName, user_id):
        print("In userDetails ", projectName, user_id)
        response = {}

        db = db_lookup(projectName)
        conn = connect(db)
        
        data = request.get_json(force=True)
        print("Input Data: ", data)

        query = f"""
                SELECT user_uid
                    , email
                    , first_name
                    , last_name
                    , google_auth_token
                    , google_refresh_token 
                FROM {db}.users 
                WHERE user_uid = '{user_id}';
                """
        print(query)

        response = execute(query, 'get', conn)
        print(response)

        return response, 200



    # def get(self, projectName, user_id):
    #     print("In userDetails")
    #     response = {}
      
    #     items = {}
    #     if projectName == 'PM':
    #         conn = connect('pm')
    #         if user_id[0] == '1':
    #             query = """SELECT 
    #             user_uid
    #             , email
    #             , first_name
    #             , last_name
    #             , google_auth_token
    #             , google_refresh_token FROM users WHERE user_uid = \'""" + user_id + """\' """

    #             response = execute(query, 'get', conn)

    #         elif user_id[0] == '3':
    #             query = """SELECT 
    #             user_uid
    #             , email
    #             , first_name
    #             , last_name
    #             , google_auth_token
    #             , google_refresh_token FROM tenantProfileInfo t
    #                                 LEFT JOIN
    #                                 users u
    #                                  ON t.tenant_user_id = u.user_uid WHERE tenant_id = \'""" + user_id + """\' """

    #             response = execute(query, 'get', conn)

    #         else:
    #             query = """ SELECT business_uid
    #                                 , business_email
    #                                 , business_name FROM businesses WHERE business_uid = \'""" + user_id + """\' """
    #             business_email = execute(query, 'get', conn)
    #             query = """SELECT user_uid
    #                                 , email
    #                                 , first_name
    #                                 , last_name
    #                                 , google_auth_token
    #                                 , google_refresh_token FROM users WHERE email = \'""" + business_email['result'][0]['business_email'] + """\' """
    #             response = execute(query, 'get', conn)
    #         return response
    #     elif projectName == 'MYSPACE-DEV':
      
    #         conn = connect('space_dev')
    #         if user_id[0] == '1':
    #             query = """
    #                 SELECT user_uid
    #                 , email
    #                 , first_name
    #                 , last_name
    #                 , google_auth_token
    #                 , google_refresh_token 
    #             FROM space_dev.users 
    #             WHERE user_uid = \'""" + user_id + """\' 
    #             """

    #             response = execute(query, 'get', conn)

    #         elif user_id[0] == '3':
    #             query = """
    #                 SELECT user_uid
    #                 , email
    #                 , first_name
    #                 , last_name
    #                 , google_auth_token
    #                 , google_refresh_token 
    #                 FROM space_dev.tenantProfileInfo t
    #                 LEFT JOIN space_dev.users u ON t.tenant_user_id = u.user_uid 
    #                 WHERE tenant_id = \'""" + user_id + """\' 
    #                 """

    #             response = execute(query, 'get', conn)

    #         else:
    #             query = """ 
    #                 SELECT business_uid
    #                 , business_email
    #                 , business_name 
    #                 FROM space_dev.businessProfileInfo 
    #                 WHERE business_uid = \'""" + user_id + """\' 
    #                 """
    #             business_email = execute(query, 'get', conn)
    #             query = """
    #                 SELECT user_uid
    #                 , email
    #                 , first_name
    #                 , last_name
    #                 , google_auth_token
    #                 , google_refresh_token 
    #                 FROM space_dev.users 
    #                 WHERE email = \'""" + business_email['result'][0]['business_email'] + """\' 
    #                 """
    #             response = execute(query, 'get', conn)
    #         return response
    #     elif projectName == 'MYSPACE':
          
    #         conn = connect('space_prod')
    #         if user_id[0] == '1':
    #             query = """
    #                 SELECT user_uid
    #                 , email
    #                 , first_name
    #                 , last_name
    #                 , google_auth_token
    #                 , google_refresh_token 
    #             FROM space_prod.users 
    #             WHERE user_uid = \'""" + user_id + """\' 
    #             """

    #             response = execute(query, 'get', conn)

    #         elif user_id[0] == '3':
    #             query = """
    #                 SELECT user_uid
    #                 , email
    #                 , first_name
    #                 , last_name
    #                 , google_auth_token
    #                 , google_refresh_token 
    #                 FROM space_prod.tenantProfileInfo t
    #                 LEFT JOIN space_prod.users u ON t.tenant_user_id = u.user_uid 
    #                 WHERE tenant_id = \'""" + user_id + """\' 
    #                 """

    #             response = execute(query, 'get', conn)

    #         else:
    #             query = """ 
    #                 SELECT business_uid
    #                 , business_email
    #                 , business_name 
    #                 FROM space_prod.businessProfileInfo 
    #                 WHERE business_uid = \'""" + user_id + """\' 
    #                 """
    #             business_email = execute(query, 'get', conn)
    #             query = """
    #                 SELECT user_uid
    #                 , email
    #                 , first_name
    #                 , last_name
    #                 , google_auth_token
    #                 , google_refresh_token 
    #                 FROM space_prod.users 
    #                 WHERE email = \'""" + business_email['result'][0]['business_email'] + """\' 
    #                 """
    #             response = execute(query, 'get', conn)
    #         return response
    #     elif projectName == 'EVERY-CIRCLE':
    #         conn = connect('every_circle')
    #         query = None

    #         query = ("""
    #                 SELECT user_unique_id
    #                 , user_email_id
    #                 , user_first_name
    #                 , user_last_name
    #                 , google_auth_token
    #                 , google_refresh_token
    #                 FROM users WHERE user_unique_id = \'""" + user_id + """\';
    #                 """)
    #         items = execute(query, "get", conn)
    #         response["message"] = "successful"
    #         response["user_unique_id"] = items["result"][0]["user_unique_id"]
    #         response["user_first_name"] = items["result"][0]["user_first_name"]
    #         response["user_last_name"] = items["result"][0]["user_last_name"]
    #         response["user_email_id"] = items["result"][0]["user_email_id"]
    #         response["google_auth_token"] = items["result"][0]["google_auth_token"]
    #         response["google_refresh_token"] = items["result"][0][
    #             "google_refresh_token"
    #         ]

    #         return response, 200
    #     elif projectName == 'SKEDUL':
    #         conn = connect('skedul')
    #         query = None

    #         query = ("""
    #                 SELECT user_unique_id
    #                 , user_email_id
    #                 , user_first_name
    #                 , user_last_name
    #                 , google_auth_token
    #                 , google_refresh_token
    #                 FROM users WHERE user_unique_id = \'""" + user_id + """\';
    #                 """)
    #         items = execute(query, "get", conn)
    #         response["message"] = "successful"
    #         response["user_unique_id"] = items["result"][0]["user_unique_id"]
    #         response["user_first_name"] = items["result"][0]["user_first_name"]
    #         response["user_last_name"] = items["result"][0]["user_last_name"]
    #         response["user_email_id"] = items["result"][0]["user_email_id"]
    #         response["google_auth_token"] = items["result"][0]["google_auth_token"]
    #         response["google_refresh_token"] = items["result"][0][
    #             "google_refresh_token"
    #         ]

    #         return response, 200
    #     elif projectName == 'FINDME':
    #         conn = connect('find_me')
    #         query = """SELECT 
    #             user_uid
    #             , email
    #             , first_name
    #             , last_name
    #             , phone_number
    #             , google_auth_token
    #             , google_refresh_token FROM users u
    #             WHERE user_uid = \'""" + user_id + """\' """

    #         response = execute(query, 'get', conn)
    #         return response


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


# -- MIDDLEWARE FUNCTIONS -------------------------------------------------------------------------------
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





if __name__ == "__main__":
    # app.run()
    app.run(host="127.0.0.1", port=2000)
