from flask_jwt_extended import create_access_token, create_refresh_token
from datetime import datetime, timedelta
import os
import hashlib
from hashlib import sha256, sha512
from getProfile import getBusinessProfileInfo, getTenantProfileInfo, getOwnerProfileInfo

def getHash(value):
    """
    Creates a hash of the given value using SHA512.
    
    Args:
        value: The value to hash
        
    Returns:
        str: The hexadecimal representation of the hash
    """
    return sha512(str(value).encode("utf-8")).hexdigest()

def createSalt():
    """
    Creates a random salt for password hashing.
    
    Returns:
        str: A hashed random value
    """
    return getHash(os.urandom(16))

def createHash(password, salt):
    """
    Creates a hash of the password using the provided salt.
    
    Args:
        password (str): The password to hash
        salt (str): The salt to use
        
    Returns:
        str: The hexadecimal representation of the hashed password
    """
    return getHash(password + salt)

def createTokens(user, projectName):
    """
    Creates access and refresh tokens for a user, including their profile information.
    
    Args:
        user (dict): User information including profile details
        projectName (str): Name of the project
        
    Returns:
        tuple: (access_token, refresh_token) containing user profile information
    """
    print('IN CREATETOKENS')

    businesses = getBusinessProfileInfo(user, projectName)['result']
    # print("1")
    tenant_id = getTenantProfileInfo(user, projectName)['result']
    # print("2")
    owner_id = getOwnerProfileInfo(user, projectName)['result']
    # print("3")

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
        'cookies': user['cookies']
    }

    # Create tokens with the full user info
    access_token = create_access_token(identity=userInfo)
    refresh_token = create_refresh_token(identity=userInfo)

    return access_token, refresh_token 