#!/usr/bin/env python3

import json
import requests
import jwt
from jwt.algorithms import RSAAlgorithm

class TokenVerifier():

    def __init__(self, id_token):
        self.id_token = id_token

    def get_public_key(self, jwks_url, kid):
        """Retrieve the public key from JWKS for a given kid."""
        jwks = requests.get(jwks_url).json()
        key = next((item for item in jwks["keys"] if item["kid"] == kid), None)
        if key:
            return RSAAlgorithm.from_jwk(json.dumps(key))

    def verify_cognito_token(self):

        client_secret_path = 'client_secret.json'
        with open(client_secret_path, 'r') as file:
            data = json.load(file)

        jwks_url = data.get('public_key_url')
        clientID = data.get('client_id')

        # Decode the header to find the kid and algorithm without verification
        headers = jwt.get_unverified_header(self.id_token)
        
        # Get the public key
        public_key = self.get_public_key(jwks_url, headers['kid'])
        
        # Decode and verify the token
        return jwt.decode(self.id_token, public_key, algorithms=["RS256"], audience=clientID, options={"verify_exp": False})



