import requests
import datetime
import json
import base64
import os

# Set the URL for the Identity domain endpoint
url = 'https://i#########' # replace {region} with your OCI region, e.g. us-phoenix-1

# Set the path to your OCI API private key file
private_key_file = r'C:\Users\gautmish\%HOMEDRIVE%%HOMEPATH%\.oci\gautam.mishra@oracle.com_2023-03-24T20_20_54.268Z.pem'

# Set the values for your OCI tenant, user, and compartment
tenant_id = 'ocid1.tenancy.oc1..###################'
user_id = 'ocid1.user.oc1..#############'
compartment_id = 'ocid1.compartment.oc1..################'

# Load the contents of the private key file
with open(private_key_file, 'r') as f:
    private_key = f.read()

# Set the payload for the token request
payload = {
    'alg': 'RS256',
    'typ': 'JWT'
}

# Set the header for the token request
header = {
    'alg': 'RS256',
    'typ': 'JWT',
    'kid': os.environ['OCI_API_KEY_ID']
}

# Set the expiration time for the token
exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

# Set the payload for the JWT
jwt_payload = {
    'iss': user_id,
    'sub': user_id,
    'aud': url + '/oauth2/token',
    'exp': exp.strftime('%s'),
    'iat': datetime.datetime.utcnow().strftime('%s'),
    'jti': base64.b64encode(os.urandom(32)).decode('utf-8')
}

# Create the JWT
jwt = json.dumps(payload, separators=(',', ':')) + '.' + json.dumps(jwt_payload, separators=(',', ':'))
jwt_sig = base64.urlsafe_b64encode(private_key.sign(jwt.encode(), padding.PKCS1v15(), hashes.SHA256())).decode('utf-8')
jwt += '.' + jwt_sig

# Set the data for the token request
data = {
    'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    'assertion': jwt
}

# Send the token request and get the response
response = requests.post(url + '/oauth2/token', data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})

# Print the access token from the response
print(response.json()['access_token'])
