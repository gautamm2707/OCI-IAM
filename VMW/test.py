import json
import requests
import base64
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def get_encoded(clid, clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    #print("Base64encoded string:", baseencoded)
    return baseencoded

def get_access_token(url,header):
    parameter = {'grant_type': "client_credentials"}
    response = requests.post(url, headers=header, params=parameter,verify=False)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

def get_auth_code(url1,clid1,redirect_uri):
    parameter = {'response_type': "code", 'client_id': clid1, 'redirect_uri': redirect_uri, 'scope': "openid+user+email"}
    jsonresponse = requests.post(url1, params=parameter,verify=False)
    """response = jsonresponse.text
    soup = BeautifulSoup(response, "html.parser")
    print(soup)"""
    jsonresp = json.loads(jsonresponse.content)
    print(type(jsonresp))





api_urlbase = "https://myvmware.######.com/SAAS/"
clid = "###################"
clsecret = "##################"
redirect_uri = "https://lumberjack.apps.itcna.############/oauth"
encodedtoken = get_encoded(clid, clsecret)
extra1 = "auth/oauth2/authorize"
extra2 = "auth/oauthtoken"

headers = {'Content-Type' : 'application/x-www-form-urlencoded' , 'Authorization' : 'Basic %s' % encodedtoken}
auth_token = get_auth_code(api_urlbase+extra1, clid,redirect_uri)
#accesstoken = get_access_token(api_urlbase+extra2,headers)

#print(accesstoken)