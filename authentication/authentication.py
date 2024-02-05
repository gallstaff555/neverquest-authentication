#!/usr/bin/env python3

from flask import Flask,jsonify,request
import boto3,hmac,hashlib,base64,json

client = boto3.client('cognito-idp')
#client_id = '5k67sb7v1d0erb46fjv8qojrlo'
#client_secret = 's03em16o477j85uqt7j1oq9pr0b1ul9t5a3ok234bkt8dm7enp5'
client_secret_path = 'client_secret.json'

with open(client_secret_path, 'r') as file:
    data = json.load(file)

client_id = data.get('client_id')
client_secret = data.get('client_secret')

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
    return jsonify(response)

app.run(host='0.0.0.0', port=8080)