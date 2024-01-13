import requests
from dotenv import load_dotenv
import os
load_dotenv()


def get_id_token(authorization_code):
    token_endpoint = 'https://accounts.google.com/o/oauth2/token'
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    redirect_uri = 'https://developers.google.com/oauthplayground'
    token_request_data = {
        'code': authorization_code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }
    token_response = requests.post(token_endpoint, data=token_request_data)
    token_data = token_response.json()
    id_token = token_data.get('id_token')
    return id_token
