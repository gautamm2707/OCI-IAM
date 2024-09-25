
"""Written for creating a confidential application for EBS in IDCS"""

import json
import requests
import base64
import urllib3
from zipfile import ZipFile
import shutil
from pathlib import Path
urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'

#Base64 encoding

def get_encoded(clid,clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    return baseencoded

#generating access token

def get_access_token(url,header):

    para = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
    response = requests.post(url, headers=header,data=para, verify=False)
    print(response.json)
    jsonresp = json.loads(response.content)
    access_token = jsonresp.get('access_token')
    return access_token

api_urlbase = "https://idcs-39511659571c4cfe9f827e9a156d3e97.identity.oraclecloud.com"
clid = "3d878a2987f04d1f854d52ff1cdfa970"
clsecret = "73c81b64-2811-41f6-8487-f2e06f3e94ef"
encodedtoken = get_encoded(clid, clsecret)
extra = "/oauth2/v1/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)

#Create a confidential application

searchurl = "https://idcs-39511659571c4cfe9f827e9a156d3e97.identity.oraclecloud.com/admin/v1/Apps"
headers2 = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
para =json.dumps({
  "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:App"],
  "basedOnTemplate": { "value": "CustomWebAppTemplateId" },
  "displayName": "a1",
  "description": "Confidential client application for testing purposes",
  "clientType": "confidential",
  "isOAuthClient": True,
  "allowedGrants": ["authorization_code","client_credentials"],
  "landingPageUrl": "https://ebsasserter.example.com:7004/dev",
  "active": True,
  "grantedAppRoles": ["Identity Domain Administrator"],
  "redirectUris": ["https://ebsasserter.example.com:7004/dev/response"],
  "logoutUri": "https://ebsasserter.example.com:7004/dev/logout",
  "postLogoutRedirectUris": ["https://ebsasserter.example.com:7004/dev"]

})
resp = requests.post(searchurl, headers=headers2, verify=False, data=para)
jsonresp = json.loads(resp.content)
clientID = jsonresp.get("name")
clientSecret = jsonresp.get("clientSecret")
print(clientID)
print(clientSecret)