import json, boto3, os, hmac, hashlib, base64

def lambda_handler(event, context):

    
    client = boto3.client('cognito-idp', region_name='us-west-2')
    client_id = os.environ.get('client_id')
    client_secret = os.environ.get('client_secret')
    
    body = json.loads(event.get('body', '{}'))
    username = body.get('username')
    confirmation_code = body.get('confirmation_code')
    secretHash = calculateSecretHash(client_id, client_secret, username)
    
    response = client.confirm_sign_up(
        ClientId=client_id,
        SecretHash=secretHash,
        Username=username,
        ConfirmationCode=confirmation_code
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }
    
def calculateSecretHash(client_id, client_secret, username):
    key = bytes(client_secret, 'utf-8')
    message = bytes(f'{username}{client_id}', 'utf-8')
    return base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()
    