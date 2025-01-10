import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import json
import base64
from dotenv import load_dotenv
from flask import request, jsonify
from werkzeug.datastructures import FileStorage, ImmutableMultiDict
from io import BytesIO

# Load environment variables
load_dotenv()
AES_SECRET_KEY = os.getenv('AES_SECRET_KEY')
AES_KEY = AES_SECRET_KEY.encode('utf-8')
BLOCK_SIZE = int(os.getenv('BLOCK_SIZE'))

def encrypt_dict(data_dict):
    """
    Encrypts a dictionary using AES encryption in CBC mode with PKCS7 padding.
    
    Args:
        data_dict (dict): The dictionary to encrypt
        
    Returns:
        str: Base64 encoded encrypted data with IV prepended, or None if encryption fails
    """
    try:
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

def decrypt_dict(encrypted_blob):
    """
    Decrypts an encrypted blob back into a dictionary.
    
    Args:
        encrypted_blob (str): Base64 encoded encrypted data with IV prepended
        
    Returns:
        dict: The decrypted dictionary, or None if decryption fails
    """
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

def handle_encrypted_request(request):
    """
    Handles decryption of incoming request data, whether it's JSON or form data.
    
    Args:
        request: Flask request object
        
    Returns:
        dict: Decrypted data if encryption exists, None otherwise
    """
    if request.is_json:
        encrypted_data = request.get_json().get('encrypted_data')
        form_data = request.get_json().get('data_type')  # True = Form data, False = JSON data
        if encrypted_data and form_data == False:
            return decrypt_dict(encrypted_data)
    elif request.content_type and request.content_type.startswith('multipart/form-data'):
        encrypted_data = request.form.get('encrypted_data')
        if encrypted_data:
            decrypted_data = decrypt_dict(encrypted_data)
            fields = {}
            files = {}

            # Process decrypted form data
            for key, value in decrypted_data.items():
                if isinstance(value, dict) and 'fileName' in value and 'fileType' in value:
                    # Handle file data
                    file_binary = base64.b64decode(value['fileData'])
                    file_stream = BytesIO(file_binary)
                    files[key] = FileStorage(
                        stream=file_stream,
                        filename=value['fileName'],
                        content_type=value['fileType']
                    )
                else:
                    fields[key] = value

            # Update request form and files
            request.form = ImmutableMultiDict(fields)
            request.files = ImmutableMultiDict(files)
            return decrypted_data
    return None

def create_json_override(decrypted_data):
    """
    Creates a function that overrides request.get_json() to return decrypted data.
    
    Args:
        decrypted_data (dict): The decrypted data to return
        
    Returns:
        function: Override function for request.get_json()
    """
    def get_json_override(*args, **kwargs):
        return decrypted_data
    return get_json_override 

def encrypt_response(data):
    """
    Encrypts response data before sending it to the frontend.
    
    Args:
        data (dict): The response data to encrypt
        
    Returns:
        Response: Flask response with encrypted data
    """
    encrypted_data = encrypt_dict(data)
    return jsonify({'encrypted_data': encrypted_data})

def handle_before_request(project_name, full_encryption_projects, postman_secret):
    """
    Handles request preprocessing, including decryption if needed.
    
    Args:
        project_name (str): Name of the current project
        full_encryption_projects (list): List of projects requiring encryption
        postman_secret (str): Secret key for Postman requests
        
    Returns:
        bool: Whether encryption should be enabled
    """
    if project_name in full_encryption_projects and request.headers.get("Postman-Secret") != postman_secret:
        print("In Middleware before_request for MYSPACE")
        decrypt_request()
        return True
    return False

def handle_after_request(response, project_name, full_encryption_projects, postman_secret, encrypt_flag):
    """
    Handles response postprocessing, including encryption if needed.
    
    Args:
        response: Flask response object
        project_name (str): Name of the current project
        full_encryption_projects (list): List of projects requiring encryption
        postman_secret (str): Secret key for Postman requests
        encrypt_flag (bool): Whether encryption is currently enabled
        
    Returns:
        Response: Processed Flask response
    """
    if project_name in full_encryption_projects and request.headers.get("Postman-Secret") != postman_secret:
        print("In Middleware after_request")
        original_status_code = response.status_code
        
        if response.is_json:
            response = encrypt_response(response.get_json())
            response.status_code = original_status_code
            
    return response

def get_project_name_from_request():
    """
    Extracts project name from the request.
    
    Returns:
        str: Project name if found in request, None otherwise
    """
    if request.view_args and "projectName" in request.view_args:
        return request.view_args["projectName"]
    return None 