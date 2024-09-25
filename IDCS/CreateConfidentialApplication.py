
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


config = json.load(open('config.json'))
idcsURL = config["iamurl"]
clid = config["client_id"]
clsecret = config["client_secret"]


encodedtoken = get_encoded(clid, clsecret)
extra = "/oauth2/v1/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
accesstoken = get_access_token(idcsURL+extra, headers)
print(accesstoken)

#Create a confidential application

#searchurl1 = "https://idcs-###################.identity.oraclecloud.com/admin/v1/Apps"
extra1 = "/admin/v1/Apps"
headers1 = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
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
resp = requests.post(idcsURL+extra1, headers=headers1, verify=False, data=para)
jsonresp = json.loads(resp.content)
clientID = jsonresp.get("name")
clientSecret = jsonresp.get("clientSecret")
appID = jsonresp.get("id")
print(clientID)
print(clientSecret)

#Search for all approles in IDCS and obtain the approleID for Identity Domain Administrator

#searchurl2 = "https://idcs-###################.identity.oraclecloud.com/admin/v1/AppRoles"
extra2 = "/admin/v1/AppRoles"
headers2 = {'Accept': '*/*', 'Authorization': 'Bearer ' + accesstoken}
response = requests.request("GET", idcsURL+extra2, headers=headers2)
jsonresp1 = json.loads(response.content)
tempjsn = jsonresp1.get("Resources")
for x in tempjsn:
    displayName = x.get("displayName")
    if displayName == "Authenticator Client":
        approleID1 = x.get("id")
for x in tempjsn:
    displayName = x.get("displayName")
    if displayName == "Me":
        approleID2 = x.get("id")

#print(approleID)

#Grant the Identity Domain Administrator Role to the Confidential app created above

#searchurl3 = "https://idcs-########################.identity.oraclecloud.com/admin/v1/Grants"
extra3 = "/admin/v1/Grants"
payload = json.dumps({
  "grantee": {
    "type": "App",
    "value": appID
  },
  "app": {
    "value": "IDCSAppId"
  },
  "entitlement": {
    "attributeName": "appRoles",
    "attributeValue": approleID1
  },
  "grantMechanism": "ADMINISTRATOR_TO_APP",
  "schemas": [
    "urn:ietf:params:scim:schemas:oracle:idcs:Grant"
  ]
})

payload2 = json.dumps({
  "grantee": {
    "type": "App",
    "value": appID
  },
  "app": {
    "value": "IDCSAppId"
  },
  "entitlement": {
    "attributeName": "appRoles",
    "attributeValue": approleID2
  },
  "grantMechanism": "ADMINISTRATOR_TO_APP",
  "schemas": [
    "urn:ietf:params:scim:schemas:oracle:idcs:Grant"
  ]
})
headers3 = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
response1 = requests.request("POST", idcsURL+extra3, headers=headers3, data=payload)
response2 = requests.request("POST", idcsURL+extra3, headers=headers3, data=payload2)
print(response1.content)