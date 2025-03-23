from flask import request

import os
import pymysql
# import datetime
from datetime import datetime, date, timedelta
import json
import boto3
from botocore.response import StreamingBody
import calendar
from decimal import Decimal
# from datetime import date, datetime, timedelta
from werkzeug.datastructures import FileStorage
import mimetypes
import ast



def connect(RDS_DB):
    global RDS_PW
    global RDS_HOST
    global RDS_PORT
    global RDS_USER

    # print("Trying to connect to RDS (API v2)...")
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
        # print("Successfully connected to RDS. (API v2)")
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
    # print(sql, cmd, type(cmd), conn, skipSerialization)
    response = {}
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            if cmd == "get":
                # print("In get")
                result = cur.fetchall()
                # print(result)
                response["message"] = "Successfully executed SQL query."
                # Return status code of 280 for successful GET request
                response["code"] = 280
                # print(response)
                if not skipSerialization:
                    # print("in if")
                    result = serializeResponse(result)
                    # print(result)
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
        # response["sql"] = sql
        return response
    
