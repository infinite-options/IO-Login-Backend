from flask_jwt_extended import create_access_token, create_refresh_token
from datetime import datetime, timedelta
import os
import hashlib
from hashlib import sha256, sha512
from getProfile import getBusinessProfileInfo, getTenantProfileInfo, getOwnerProfileInfo

def getHash(value):
    """
    Creates a hash of the given value using SHA256.
    
    Args:
        value: The value to hash
        
    Returns:
        str: The hexadecimal representation of the hash
    """
    base = str(value).encode()
    return sha256(base).hexdigest()

def createSalt():
    """
    Creates a random salt for password hashing.
    
    Returns:
        str: A hashed random value based on current timestamp
    """
    return getHash(datetime.now())

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
        dict: Dictionary containing access_token, refresh_token, and user information
    """
    print('IN CREATETOKENS ', projectName, user)

    businesses = getBusinessProfileInfo(user, projectName)['result']
    # print("1")
    tenant_id = getTenantProfileInfo(user, projectName)['result']
    # print("2")
    owner_id = getOwnerProfileInfo(user, projectName)['result']
    # print("3")

    if not user.get('notifications'): user['notifications'] = "true"
    if not user.get('dark_mode'): user['dark_mode'] = "false"
    if not user.get('cookies'): user['cookies'] = "true"
    print('4')

    # userInfo = {
    #     'user_uid': user['user_uid'],
    #     # 'first_name': user['first_name'],
    #     # 'last_name': user['last_name'],
    #     'phone_number': user['phone_number'],
    #     'email': user['email'],
    #     'role': user['role'],
    #     'google_auth_token': user['google_auth_token'],
    #     'businesses': businesses,
    #     'tenant_id': tenant_id,
    #     'owner_id': owner_id,
    #     'notifications': user['notifications'],
    #     'dark_mode': user['dark_mode'],
    #     'cookies': user['cookies']
    # }

    # Create tokens with the full user info
    # access_token = create_access_token(identity=userInfo)
    # refresh_token = create_refresh_token(identity=userInfo)

    # Create tokens with the user info
    access_token = create_access_token(identity=user)
    refresh_token = create_refresh_token(identity=user)

    return {
        'access_token': access_token,
        'refresh_token': refresh_token
        # 'user': userInfo
    } 