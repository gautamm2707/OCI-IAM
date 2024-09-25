
"""Written for obtaining date value of lastSuccessfulSetDate + passwordExpiresAfter
and you will get the date when the password will expire next for a user"""

import json
import requests
import base64
import urllib3
import xlwt
import ExcelpandasWork as pd
from zipfile import ZipFile
import shutil
from pathlib import Path
#import openpyxl as xl
urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'


def get_encoded(clid,clsecret):
    encoded = clid + ":" + clsecret
    baseencoded = base64.urlsafe_b64encode(encoded.encode('UTF-8')).decode('ascii')
    #print("Base64encoded string:", baseencoded)
    return baseencoded
"""parameter = {"grant_type": "client_credentials", "scope":"urn:opc:idm:__myscopes__"}"""
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
#print (encodedtoken)
extra = "/oauth2/v1/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Authorization': 'Basic %s' % encodedtoken, 'Accept': '*/*'}
#print (headers)
#print (api_urlbase+extra)
accesstoken = get_access_token(api_urlbase+extra, headers)
print(accesstoken)

#Getting Total count of users and extracting id for each user

searchurl = "https://idcs-39511659571c4cfe9f827e9a156d3e97.identity.oraclecloud.com/admin/v1/Users"
headers2 = {'Authorization': 'Bearer ' + accesstoken}
#headers2 = {'Accept': '*/*', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + accesstoken}
param = {'attributes': "id"}
resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
jsonresp = json.loads(resp.content)
totalCount = jsonresp.get("totalResults")
tempjsn = jsonresp.get("Resources")
mainlist = []
for x in tempjsn:
    trimjsn = {}
    id = trimjsn['id'] = x.get("id")
    username = trimjsn['username'] = x.get("userName")
    mainlist.append(trimjsn)

    # Getting lastSuccessfulSetDate for each user
    searchurl = "https://idcs-39511659571c4cfe9f827e9a156d3e97.identity.oraclecloud.com/admin/v1/Users/"+id
    headers2 = {'Authorization': 'Bearer ' + accesstoken}
    param = {'attributes': "urn:ietf:params:scim:schemas:oracle:idcs:extension:passwordState:User:lastSuccessfulSetDate"}
    resp = requests.get(searchurl, headers=headers2, verify=False, params=param)
    jsonresp = json.loads(resp.content)
    lssd = jsonresp.get("urn:ietf:params:scim:schemas:oracle:idcs:extension:passwordState:User")
    if "urn:ietf:params:scim:schemas:oracle:idcs:extension:passwordState:User" in jsonresp:
        searchurl = "https://idcs-39511659571c4cfe9f827e9a156d3e97.identity.oraclecloud.com/admin/v1/ApplicablePasswordPolicyRetriever"
        headers2 = {'Authorization': 'Bearer ' + accesstoken, 'Content-Type': 'application/json'}
        para = {"userName": username,"schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:ApplicablePasswordPolicyRetriever"]}
        resp = requests.post(searchurl, headers=headers2, verify=False, data=para)
        jsonresp1 = json.loads(resp.content)
        print(jsonresp1)
        print(username + ", " +lssd['lastSuccessfulSetDate'])
    else:
        continue
    """if jsonresp['lssd']:
        print("None")
    else:
        print(lssd)"""

    #print(jsonresp)
print(mainlist)
print(totalCount)







