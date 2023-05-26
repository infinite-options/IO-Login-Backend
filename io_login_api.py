import json
import os
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

app = Flask(__name__)
CORS(app)

# API
api = Api(app)

RDS_HOST = "io-mysqldb8.cxjnrciilyjq.us-west-1.rds.amazonaws.com"
RDS_PORT = 3306
RDS_USER = "admin"
RDS_PW = "prashant"

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
            host=RDS_HOST,
            user=RDS_USER,
            port=RDS_PORT,
            passwd=RDS_PW,
            db=RDS_DB,
            cursorclass=pymysql.cursors.DictCursor,
        )
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


def getEmployeeBusinesses(user):
    response = {}
    conn = connect('pm')
    query = """SELECT b.*, e.employee_role
        FROM employees e LEFT JOIN businesses b ON e.business_uid = b.business_uid
        WHERE user_uid = \'""" + user['user_uid'] + """\'"""

    response = execute(query, "get", conn)
    return response


def getTenantProfileInfo(user):
    response = {}
    conn = connect('pm')
    query = """ SELECT tenant_id FROM tenantProfileInfo
            WHERE tenant_user_id = \'""" + user['user_uid'] + """\'"""

    response = execute(query, "get", conn)
    return response


def getHash(value):
    base = str(value).encode()
    return sha256(base).hexdigest()


def createSalt():
    return getHash(datetime.now())


def createHash(password, salt):
    return getHash(password+salt)


def createTokens(user):
    print('IN CREATETOKENS')

    businesses = getEmployeeBusinesses(user)['result']
    tenant_user_id = getTenantProfileInfo(user)['result']

    userInfo = {
        'user_uid': user['user_uid'],
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'phone_number': user['phone_number'],
        'email': user['email'],
        'role': user['role'],
        'google_auth_token': user['google_auth_token'],
        'businesses': businesses,
        'tenant_id': tenant_user_id
    }

    return {
        'access_token': create_access_token(userInfo),
        'refresh_token': create_refresh_token(userInfo),
        'user': userInfo
    }


def getUserByEmail(email, projectName):
    if projectName == "PM":
        conn = connect('pm')
        # get user
        user_lookup_query = ("""
        SELECT * FROM pm.users
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


def createUser(firstName, lastName, phoneNumber, email, password, role, email_validated=None, google_auth_token=None, google_refresh_token=None, social_id=None, access_expires_in=None, projectName=None):
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

        response = execute(query, "post", conn)
        return newUser
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


# Get the correct users for a project
class GetUsers(Resource):

    def get(self, projectName):
        response = {}
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
            sendEmail('pm', recipient, subject, body)
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
            sendEmail('nitya', recipient, subject, body)
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
            sendEmail('skedul', recipient, subject, body)
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
            sendEmail('find_me', recipient, subject, body)
            response['message'] = "A temporary password has been sent"
        return response


class UpdateEmailPassword(Resource):
    def post(self, projectName):
        response = {}
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
        return response


class AccountSalt(Resource):
    def post(self, projectName):
        response = {}
        items = {}
        data = request.get_json(force=True)
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
        return items


class Login(Resource):
    def post(self, projectName):
        response = {}
        data = request.get_json(force=True)
        email = data["email"]
        password = data.get("password")
        if projectName == 'PM':
            conn = connect('pm')
            user = getUserByEmail(email, projectName)
            if user:
                if password == user['password_hash']:
                    response['message'] = 'Login successful'
                    response['code'] = 200
                    response['result'] = createTokens(user)
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

        return response


class CreateAccount(Resource):
    def post(self, projectName):
        response = {}
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
                response['result'] = createTokens(user)
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

#  updating access token if expired


class UpdateAccessToken(Resource):
    def post(self, projectName, user_id,):
        print("In UpdateAccessToken")
        response = {}
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


class UserDetails(Resource):
    def get(self, projectName, user_id):
        print("In userDetails")
        response = {}
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
        print("In create new user")
        response = {}
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
                response['result'] = createTokens(user)
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
            return response


# user social login
class UserSocialLogin(Resource):
    def get(self, projectName, email_id):
        print("In UserSocialLogin")
        response = {}
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
# login endpoints
api.add_resource(AccountSalt, "/api/v2/AccountSalt/<string:projectName>")
api.add_resource(Login, "/api/v2/Login/<string:projectName>")
# update password
api.add_resource(
    SetTempPassword, "/api/v2/SetTempPassword/<string:projectName>")
api.add_resource(UpdateEmailPassword,
                 "/api/v2/UpdateEmailPassword/<string:projectName>")
# token endpoints
api.add_resource(UpdateAccessToken,
                 "/api/v2/UpdateAccessToken/<string:projectName>/<string:user_id>")
api.add_resource(
    UserToken, "/api/v2/UserToken/<string:projectName>/<string:user_email_id>")
# get info endpoints
api.add_resource(
    UserDetails, "/api/v2/UserDetails/<string:projectName>/<string:user_id>")
api.add_resource(
    UserDetailsByEmail, "/api/v2/UserDetailsByEmail/<string:projectName>/<string:email_id>")
api.add_resource(
    GetEmailId, "/api/v2/GetEmailId/<string:projectName>/<string:user_id>")
api.add_resource(GetUsers, "/api/v2/GetUsers/<string:projectName>")

# social signup and login endpoints
api.add_resource(UserSocialSignUp,
                 "/api/v2/UserSocialSignUp/<string:projectName>")
api.add_resource(
    UserSocialLogin, "/api/v2/UserSocialLogin/<string:projectName>/<string:email_id>")
api.add_resource(
    SendEmail, "/api/v2/SendEmail")
api.add_resource(
    CheckEmailValidationCode, "/api/v2/CheckEmailValidationCode/<string:projectName>")

if __name__ == "__main__":
    # app.run()
    app.run(host="127.0.0.1", port=2000)
