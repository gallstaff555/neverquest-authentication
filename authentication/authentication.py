#!/usr/bin/env python3

from flask import Flask,jsonify,request
from token_verifier import TokenVerifier
import boto3,hmac,hashlib,base64,json,jwt
from botocore.exceptions import ClientError

client = boto3.client('cognito-idp', region_name='us-west-2')
client_secret_path = 'client_secret.json'

with open(client_secret_path, 'r') as file:
    data = json.load(file)

client_id = data.get('client_id')
client_secret = data.get('client_secret')
user_pool_id = data.get('user_pool_id')

print(client_id)
print(client_secret)

app = Flask(__name__)

def calculateSecretHash(client_id, client_secret, username):
    key = bytes(client_secret, 'utf-8')
    message = bytes(f'{username}{client_id}', 'utf-8')
    return base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()

@app.route('/create_account', methods=['POST'])
def create_account():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    secretHash = calculateSecretHash(client_id, client_secret, username)
    
    response = client.sign_up(
        ClientId=client_id,
        SecretHash=secretHash,
        Username=f'{username}',
        Password=f'{password}',
        UserAttributes=[
            {
                'Name': 'email',
                'Value': f'{email}'
            },
        ],
    )

    print(response)
    return jsonify(response)
   

@app.route('/confirm_account', methods=['POST'])
def confirm_account():
    data = request.get_json()
    username = data.get('username')
    confirmation_code = data.get('confirmation_code')
    secretHash = calculateSecretHash(client_id, client_secret, username)
    
    response = client.confirm_sign_up(
        ClientId=client_id,
        SecretHash=secretHash,
        Username=username,
        ConfirmationCode=confirmation_code
    )
    
    status_code = response['ResponseMetadata']['HTTPStatusCode']
    print(status_code)
    return jsonify(response)

@app.route('/request_token', methods=['POST'])
def login():
    try: 
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        secretHash = calculateSecretHash(client_id, client_secret, username)
        
        cognito_response = client.admin_initiate_auth(
            UserPoolId=user_pool_id,  
            ClientId=client_id,  
            
            # This auth flow allows you to directly submit user credentials
            AuthFlow='ADMIN_USER_PASSWORD_AUTH',  
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password, 
                'SECRET_HASH': secretHash
        })
        
        auth_result = cognito_response['AuthenticationResult']
        return jsonify(auth_result), 200
    except ClientError as e:
        # handle specific AWS Cognito errors
        error_message = e.response['Error']['Message']
        return jsonify({'Cognito error': error_message}), 500
    except Exception as e:
        # Handle other errors
        return jsonify({'Error': str(e)}), 500

@app.route('/login', methods=['POST'])
def decode():
    data = request.get_json()
    id_token = data.get('IdToken')
    verifier = TokenVerifier(id_token)
    #print(f'original id token: {id_token}\n')
    result = verifier.verify_cognito_token()
    return result

app.run(host='0.0.0.0', port=8080)